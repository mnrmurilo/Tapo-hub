"""Verify encrypted hub queries and playback of owned footage; no camera requests."""
from datetime import datetime
import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import hashlib
import re
from urllib.parse import urlencode
from urllib.request import parse_http_list, parse_keqv_list
from zoneinfo import ZoneInfo

from camera_media import STORE, headers, digest, decrypt_media
from camera_probe import CameraProbe
from playback_media import encrypt
from recording_playback import DETECTION_ALARMS


def http_response(stream):
    line = stream.readline(4097)
    code = int(line.split()[1])
    return code, headers(stream)


def stream_clip(port, password_hash, query, output, command="playback", device_id=None, route_mac=None, bare_stream=False):
    with socket.create_connection(("10.23.0.72", port), timeout=10) as raw:
        if port == 443:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = context.wrap_socket(raw, server_hostname="tapo-hub-lab")
        else:
            connection = raw
        with connection, connection.makefile("rb") as stream:
            route = {"playerId": "automated-check"}
            if device_id is not None:
                route["deviceId"] = device_id
            if route_mac is not None:
                from camera_registry import normalize_mac
                route['camera_mac'] = normalize_mac(route_mac).replace(':', '').upper()
            uri = "/stream" if bare_stream else "/stream?" + urlencode(route)
            request = (b"POST " + uri.encode() + b" HTTP/1.1\r\nHost: tapo-hub-lab\r\n"
                       b"Content-Type: multipart/mixed;boundary=--client-stream-boundary--\r\n"
                       b"Connection: keep-alive\r\nContent-Length: -1\r\n")
            connection.sendall(request + b"\r\n")
            code, fields = http_response(stream)
            assert code == 401, "Playback must require digest authentication"
            assert stream.read(int(fields.get("content-length", 0))) == b""
            proof = digest(fields["www-authenticate"], password_hash, "AUTOMATED-PLAYBACK-CHECK")
            auth = parse_keqv_list(parse_http_list(proof[7:]))
            md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
            response = md5(":".join((md5("admin:" + auth["realm"] + ":" + password_hash), auth["nonce"],
                auth["nc"], auth["cnonce"], "auth", md5("POST:" + uri))))
            proof = proof.replace('uri="/stream"', 'uri="' + uri + '"').replace(auth["response"], response)
            connection.sendall(request + b"Authorization: " + proof.encode() + b"\r\n\r\n")
            code, fields = http_response(stream)
            assert code == 200
            key_exchange = fields["key-exchange"]
            assert 'cipher="AES_128_CBC"' in key_exchange and 'padding="PKCS7_16"' in key_exchange
            assert 'algorithm="MD5"' in key_exchange
            boundary = fields["content-type"].split("boundary=", 1)[1].encode()
            body = json.dumps({"type": "request", "seq": 7, "params": {"method": "get", command: query}}).encode()
            exchange = parse_keqv_list(parse_http_list(key_exchange.replace(" ", ",")))
            body = encrypt(body, exchange["nonce"], password_hash)
            connection.sendall(b"--client-stream-boundary--\r\nContent-Type: application/json\r\nX-If-Encrypt: 1\r\nContent-Length: "
                               + str(len(body)).encode() + b"\r\n\r\n" + body + b"\r\n")
            total, finished, deadline = 0, False, time.monotonic() + 140
            with output.open("wb") as target:
                while time.monotonic() < deadline:
                    assert stream.readline(129) == boundary + b"\r\n", "Missing multipart response"
                    fields = headers(stream)
                    size = int(fields["content-length"])
                    assert 0 < size <= 65536
                    data = stream.read(size)
                    assert len(data) == size and stream.read(2) == b"\r\n"
                    if fields["content-type"] in ("video/mp2t", "image/jpeg"):
                        assert fields["x-if-encrypt"] == "1", "Footage must be encrypted on the LAN"
                        plain = decrypt_media(data, key_exchange, password_hash)
                        if fields["content-type"] == "video/mp2t":
                            assert command == "playback" and len(plain) % 188 == 0 and plain[0] == 0x47
                        else:
                            assert command in ("download", "image") and plain.startswith(b"\xff\xd8") and plain.endswith(b"\xff\xd9")
                        total += len(plain)
                        assert total <= 30_000_000
                        target.write(plain)
                    else:
                        message = json.loads(data)
                        assert message.get("params", {}).get("error_code", 0) == 0
                        if message.get("params", {}).get("status") == "finished":
                            finished = True
                            break
            assert total > 0 and finished, "Playback did not finish cleanly"
            return total


def frame_hashes(path):
    data = subprocess.check_output(["ffmpeg", "-v", "error", "-nostdin", "-i", str(path),
                                    "-map", "0:v:0", "-an", "-f", "framemd5", "-"], timeout=30)
    return [line.rsplit(b",", 1)[-1].strip() for line in data.splitlines() if line and not line.startswith(b"#")]


def select_recording(directory, mac, file_id=None):
    if file_id is not None and not re.fullmatch(r'event-[0-9a-f]{24}', file_id):
        raise ValueError('Invalid playback verification recording key')
    rows = []
    for path in directory.glob('*.mp4.json'):
        try:
            if path.is_symlink() or path.stat().st_size > 2_000_000:
                continue
            details = json.loads(path.read_text())
            media = Path(str(path)[:-5])
            if (details.get('camera_mac') == mac and details.get('validated_recording') is True
                    and details.get('event_type') in DETECTION_ALARMS
                    and details.get('format_version') == 1 and media.is_file() and not media.is_symlink()
                    and media.stat().st_size == details['bytes']
                    and (file_id is None or media.stem == file_id)):
                rows.append((details['source_time'], path))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    if not rows:
        raise ValueError('No matching validated recording for playback verification')
    return min(rows)[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', choices=('TD21', 'C400'), default='TD21')
    parser.add_argument('--file-id', help='Verify exactly this retained recording')
    args = parser.parse_args()
    model = args.model
    state = json.loads(Path("/var/lib/tapo-hub/state.json").read_text())
    enrolled = json.loads(Path("/var/lib/tapo-hub/enrolled.json").read_text())
    mac = next(mac for mac, item in enrolled.items() if item["device_model"] == model and item.get('hub_storage_enabled'))
    index = select_recording(STORE / 'events', mac, args.file_id)
    original = Path(str(index)[:-5])
    details = json.loads(index.read_text())
    start = details['source_time']
    duration = len(details['video_pts'])/details['rate']
    day = datetime.fromtimestamp(start, ZoneInfo(state.get("zone_id", "Etc/UTC"))).strftime("%Y%m%d")
    client = CameraProbe("10.23.0.72", state["password_hash"])
    client.login()
    result = client._request({"method": "getCircularRecordingConfig", "params": {"harddisk_manage": {"name": ["harddisk"]}}})
    assert result["result"]["harddisk_manage"]["harddisk"]["loop"] == "on"
    result = client._request({"method": "searchDateWithVideo", "params": {"playback": {"search_year_utility": {
        "start_date": day[:6] + "01", "end_date": day[:6] + "31", "channel": [0], "child_device_mac": mac}}}})
    assert any(next(iter(item.values()))["date"] == day for item in result["result"]["playback"]["search_results"])
    result = client._request({"method": "searchVideoWithUTC", "params": {"playback": {"search_video_with_utc": {
        "start_time": start, "end_time": start + 60, "channel": 0, "child_device_mac": mac}}}})
    assert any(next(iter(row.values()))["startTime"] == start for row in result["result"]["playback"]["search_video_results"])
    result = client._request({"method": "searchDetectionList", "params": {"playback": {"search_detection_list": {
        "start_time": start, "end_time": start + 60, "channel": 0, "child_device_mac": mac}}}})
    events = result["result"]["playback"]
    assert events["snapshot_enable"] and any(row["start_time"] == start and row["alarm_type"] == DETECTION_ALARMS[details['event_type']]
                                             for row in events["search_detection_list"])
    source_hashes = frame_hashes(original)
    source_probe = json.loads(subprocess.check_output(['ffprobe', '-v', 'error', '-show_entries',
        'stream=codec_type', '-of', 'json', str(original)], timeout=10))
    source_audio = any(track.get('codec_type') == 'audio' for track in source_probe['streams'])
    with tempfile.TemporaryDirectory(dir=STORE, prefix=".playback-check-") as work:
        for port in (8800, 443):
            output = Path(work) / (str(port) + ".ts")
            query = ({"channels": [0], "start_time": str(start + int(min(7, duration/2))), "camera_mac": mac.replace(":", ""),
                      "auto_seek": "1", "scale": "1/1"} if port == 8800 else
                     {"channels": [0], "start_time": str(start), "end_time": str(start + 3), "child_device_mac": mac})
            total = stream_clip(port, state["password_hash"], query, output, device_id=enrolled[mac]['device_id'])
            subprocess.run(["ffmpeg", "-v", "error", "-xerror", "-nostdin", "-i", str(output), "-f", "null", "-"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
            probe = json.loads(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries",
                "stream=codec_name,codec_type", "-of", "json", str(output)], timeout=10))
            received_audio = any(track.get("codec_type") == "audio" for track in probe["streams"])
            assert received_audio == source_audio, 'Playback audio differs from the source'
            received_hashes = frame_hashes(output)
            assert received_hashes and any(received_hashes == source_hashes[i:i+len(received_hashes)]
                                           for i in range(len(source_hashes))), "Playback frames differ from the owned source"
            print(json.dumps({"port": port, "encrypted_playback": "passed", "bytes": total,
                              "start_only_request": "end_time" not in query,
                              "video_frames_match_original": len(received_hashes), "audio_present": received_audio}), flush=True)
        image = Path(work) / "thumbnail.jpg"
        total = stream_clip(8800, state["password_hash"], {"channels": [0], "start_time": str(start),
                            "end_time": str(start), "download_type": "1", "media_type": 2}, image, command="download", device_id=enrolled[mac]['device_id'])
        assert image.read_bytes() == original.with_suffix(".jpg").read_bytes()
        subprocess.run(["ffmpeg", "-v", "error", "-xerror", "-nostdin", "-i", str(image), "-f", "null", "-"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
        print(json.dumps({"motion_event_metadata": "passed", "encrypted_thumbnail": "passed", "bytes": total}), flush=True)
    print(model + " authenticated calendar/listing and native playback passed; no camera requests sent", flush=True)


if __name__ == "__main__":
    main()
