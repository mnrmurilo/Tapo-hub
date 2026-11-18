"""Decode TD21 native event files; inputs and outputs stay on the recording volume."""
import io
import math
import re
import statistics

from camera_media import decrypt_media, headers


def nal_units(video):
    starts = list(re.finditer(b"\x00\x00(?:\x00)?\x01", video))
    return [(video[match.end()] & 31, video[match.start():starts[i+1].start() if i+1 < len(starts) else len(video)])
            for i, match in enumerate(starts) if match.end() < len(video)]


def decrypt_payload(data, nonce, password_hash, expected):
    if not re.fullmatch(r"[0-9A-Fa-f]{32}", nonce):
        raise ValueError("Invalid native media nonce")
    plain = decrypt_media(data, 'username="admin" nonce="' + nonce + '"', password_hash)
    if expected is not None and len(plain) != expected:
        raise ValueError("Native decrypted length mismatch")
    return plain


def decode_snapshot(data, nonce, password_hash, expected):
    plain = decrypt_payload(data, nonce, password_hash, expected)
    # This TD21 appends an opaque 16-byte trailer after JPEG EOI; the wire file preserves it.
    if plain[:-16].endswith(b"\xff\xd9"):
        plain = plain[:-16]
    if not plain.startswith(b"\xff\xd8") or not plain.endswith(b"\xff\xd9"):
        raise ValueError("Invalid native JPEG framing")
    return plain


def decode_stream(data, nonce, password_hash, content_type):
    match = re.fullmatch(r'multipart/x-mixed-replace;\s*boundary="?([A-Za-z0-9_-]{1,64})"?', content_type)
    if not match:
        raise ValueError("Unsupported native multipart type")
    boundary = b"--" + match[1].encode()
    stream = io.BytesIO(data)
    video, audio, types, timestamps, audio_frames, utc_times = bytearray(), bytearray(), {}, [], [], []
    pending_video = bytearray()
    width = height = rate = None
    while stream.tell() < len(data):
        line = stream.readline(129)
        if line == b"\r\n":
            continue
        if line == boundary + b"--\r\n":
            if stream.read().strip():
                raise ValueError("Unexpected native multipart epilogue")
            break
        if line != boundary + b"\r\n":
            raise ValueError("Invalid native multipart boundary")
        part = headers(stream)
        length = int(part.get("content-length", "-1"))
        if not 0 < length <= 2_000_000:
            raise ValueError("Invalid native frame length")
        payload = stream.read(length)
        if len(payload) != length:
            raise ValueError("Truncated native frame")
        kind = part.get("content-type", "")
        types[kind] = types.get(kind, 0) + 1
        if kind == "video/x-h264":
            expected = int(part["x-decrypt-length"])
            payload = decrypt_payload(payload, nonce, password_hash, expected)
            if not payload.startswith((b"\x00\x00\x00\x01", b"\x00\x00\x01")):
                raise ValueError("Invalid native H264 framing")
            timestamp = float(part["x-timestamp"])
            if not math.isfinite(timestamp) or timestamp < 0:
                raise ValueError("Invalid native frame timestamp")
            if "x-frame-width" in part:
                width, height = int(part["x-frame-width"]), int(part["x-frame-height"])
            if "x-framerate" in part:
                rate = int(part["x-framerate"])
            # Buffer headers/SEI after the final picture; alone they form an invalid empty frame.
            units = nal_units(payload)
            pictures = [i for i, (kind, _) in enumerate(units) if 1 <= kind <= 5]
            if pictures:
                stop = pictures[-1] + 1
                pending_video.extend(b''.join(unit for _, unit in units[:stop]))
                video.extend(pending_video)
                pending_video.clear()
                pending_video.extend(b''.join(unit for _, unit in units[stop:]))
                timestamps.append(timestamp)
                if "x-utctime" in part:
                    utc_times.append(int(part["x-utctime"]))
            else:
                pending_video.extend(payload)
        elif kind in ("audio/g711u", "audio/g711a"):
            # Native audio is encrypted too, despite having no X-Decrypt-Length header.
            payload = decrypt_payload(payload, nonce, password_hash, None)
            audio.extend(payload)
            timestamp = float(part["x-timestamp"])
            if not math.isfinite(timestamp) or timestamp < 0:
                raise ValueError("Invalid native audio timestamp")
            audio_frames.append((timestamp, len(payload)))
        else:
            raise ValueError("Unsupported native frame type")
    if not video or not timestamps:
        raise ValueError("Native event contained no video")
    if not rate or not 1 <= rate <= 60 or not width or not height or not 1 <= width <= 8192 or not 1 <= height <= 8192:
        raise ValueError("Invalid native video dimensions or rate")
    # C400 timestamps quantize 70ms packets to 60/80ms; estimate across several packets.
    window = min(10, len(audio_frames) - 1)
    rates = [sum(size for _, size in audio_frames[i-window:i]) / (audio_frames[i][0] - audio_frames[i-window][0])
             for i in range(window, len(audio_frames)) if window > 0 and audio_frames[i][0] > audio_frames[i-window][0]]
    audio_rate = min((8000, 16000), key=lambda value: abs(value - statistics.median(rates))) if rates else 16000
    if rates and abs(statistics.median(rates) - audio_rate) > audio_rate * 0.1:
        raise ValueError("Unsupported native audio sample rate")
    return {"video": bytes(video), "audio": bytes(audio), "frame_types": types,
            "width": width, "height": height, "rate": rate,
            "audio_rate": audio_rate, "video_pts": timestamps,
            "source_time": min(utc_times) if utc_times else None,
            "duration": round(max(timestamps) - min(timestamps), 3)}
