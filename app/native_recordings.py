"""Atomically save independently decoded TD21 event recordings on the isolated store."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from camera_media import STORE
from native_media_decode import decode_snapshot, decode_stream, nal_units
from storage_status import disk_info


def run_media(arguments):
    try:
        subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", *arguments],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
    except subprocess.SubprocessError as error:
        error.media_stage = "validate" if "-xerror" in arguments else "mux"
        raise


def save_event(body, metadata, password_hash, mac, directory=None, *, recovered_partial=False):
    if not os.path.ismount(STORE) or disk_info()["status"] != "normal" or os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize < 100_000_000:
        raise ValueError("Dedicated recording filesystem unavailable or low on space")
    directory = Path(directory) if directory is not None else STORE / "events"
    if not directory.resolve().is_relative_to(STORE.resolve()):
        raise ValueError("Native events must stay on the recording volume")
    directory.mkdir(mode=0o700, exist_ok=True)
    key = hashlib.sha256((mac + ":" + metadata["event_id"]).encode()).hexdigest()[:24]
    suffix = ".jpg" if metadata["endpoint"].endswith("alarm_snapshot") else ".mp4"
    if recovered_partial and (suffix != ".mp4" or metadata.get("transfer_complete") is not False):
        raise ValueError("Partial recovery requires an incomplete video upload")
    destination = directory / ("event-" + key + suffix)
    index = destination.with_suffix(destination.suffix + ".json")
    codec_file = directory / ".codecs" / (hashlib.sha256(mac.encode()).hexdigest()[:24] + ".json")
    if (destination.is_file() and index.is_file() and json.loads(index.read_text()).get("format_version") == 1
            and (suffix == ".jpg" or codec_file.is_file())):
        previous = json.loads(index.read_text())
        if (recovered_partial or previous.get("recovered_partial") is not True
                or metadata.get("transfer_complete") is not True):
            return {"path": str(destination), "bytes": destination.stat().st_size, "duplicate": True}
    data = Path(body).read_bytes()
    report = {"camera_mac": mac, "event_id": metadata["event_id"], "format": suffix[1:], "format_version": 1,
              "event_type": metadata.get("event_type", ""), "event_time": metadata.get("event_time", ""),
              "received_at": metadata["captured_at"], "validated_recording": suffix == ".mp4"}
    report['native_upload'] = {'transfer_complete': metadata.get('transfer_complete') is True,
                              'admission_reply_sent': metadata.get('ready_reply_sent') is True,
                              'admission_reply_seconds': metadata.get('ready_reply_elapsed_seconds')}
    report["recovered_partial"] = recovered_partial
    with tempfile.TemporaryDirectory(dir=directory, prefix=".event-") as work:
        work = Path(work)
        output = work / ("media" + suffix)
        if suffix == ".jpg":
            output.write_bytes(decode_snapshot(data, metadata["nonce"], password_hash, int(metadata["decrypt_length"])))
        else:
            decoded = decode_stream(data, metadata["nonce"], password_hash, metadata["content_type"])
            video, audio = work / "video.h264", work / "audio.g711"
            video_data = decoded.pop("video")
            parameters = {kind: nal for kind, nal in nal_units(video_data) if kind in (7, 8)}
            codec = None
            report["codec_parameters_reused"] = False
            if set(parameters) == {7, 8}:
                codec = {"width": decoded["width"], "height": decoded["height"], "rate": decoded["rate"],
                         "parameters": (parameters[7] + parameters[8]).hex()}
                if len(bytes.fromhex(codec["parameters"])) > 4096:
                    raise ValueError("Oversized H264 parameters")
            elif not parameters and codec_file.is_file():
                cached = json.loads(codec_file.read_text())
                if all(cached.get(key) == decoded.get(key) for key in ("width", "height", "rate")):
                    prefix = bytes.fromhex(cached["parameters"])
                    if len(prefix) > 4096 or {kind for kind, _ in nal_units(prefix)} != {7, 8}:
                        raise ValueError("Invalid cached H264 parameters")
                    video_data = prefix + video_data
                    report["codec_parameters_reused"] = True
            video.write_bytes(video_data)
            sound = decoded.pop("audio")
            arguments = ["-fflags", "+genpts", "-r", str(decoded["rate"]), "-f", "h264", "-i", str(video)]
            if sound:
                audio.write_bytes(sound)
                kind = "mulaw" if "audio/g711u" in decoded["frame_types"] else "alaw"
                arguments += ["-f", kind, "-ar", str(decoded["audio_rate"]), "-ac", "1", "-i", str(audio),
                              "-map", "0:v:0", "-map", "1:a:0", "-c:a", "aac", "-b:a", "32k"]
            arguments += ["-c:v", "copy", "-movflags", "+faststart", str(output)]
            run_media(arguments)
            # shortcut: MP4 uses declared frame rate; use native PTS when implementing Tapo playback.
            report.update(decoded)
        run_media(["-xerror", "-i", str(output), "-f", "null", "-"])
        probe = json.loads(subprocess.check_output([
            "ffprobe", "-v", "error", "-show_entries", "stream=codec_type,codec_name,width,height,sample_rate",
            "-of", "json", str(output)], timeout=15))
        tracks = probe.get("streams", [])
        if not any(track.get("codec_type") == "video" for track in tracks):
            raise ValueError("Validated native event has no video track")
        if suffix == ".mp4" and sound and not any(track.get("codec_type") == "audio" for track in tracks):
            raise ValueError("Native MP4 lost its audio track")
        report["verified_tracks"] = tracks
        if suffix == ".mp4" and codec is not None:
            codec_file.parent.mkdir(mode=0o700, exist_ok=True)
            temporary_codec = work / "codec.json"
            with temporary_codec.open("w") as stream:
                json.dump(codec, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_codec, 0o600)
            os.replace(temporary_codec, codec_file)
        report["bytes"] = output.stat().st_size
        with output.open("rb") as stream:
            os.fsync(stream.fileno())
        index_temp = work / "index.json"
        with index_temp.open("w") as stream:
            json.dump(report, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(output, 0o600)
        os.chmod(index_temp, 0o600)
        os.replace(output, destination)
        os.replace(index_temp, index)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return {"path": str(destination), "bytes": report["bytes"], "duplicate": False}
