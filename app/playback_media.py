"""Authenticated local Tapo multipart playback of completed TD21 MP4 files."""
import hashlib
import hmac
import json
import logging
import re
import secrets
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler
from urllib.request import parse_http_list, parse_keqv_list
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from camera_media import headers, decrypt_media
from recording_playback import integer, filter_summary
from recording_retention import activity
from camera_registry import normalize_mac

LOG = logging.getLogger("tapo-hub-lab")
BOUNDARY = b"--device-stream-boundary--"


def routed_query(handler, query):
    fields = parse_qs(urlsplit(handler.path).query, max_num_fields=16)
    storage = getattr(handler.server.playback, 'storage', None)
    records = {}
    if isinstance(getattr(storage, 'devices', None), dict):
        with storage.lock:
            records = dict(storage.devices)
    info = getattr(storage, 'device_info', {})
    if not isinstance(info, dict):
        info = {}
    def kind(value):
        if not isinstance(value, str):
            return type(value).__name__
        if any(record.get('device_id') == value for record in records.values()):
            return 'camera_id'
        if any(str(record.get('device_id', '')).casefold() == value.casefold() for record in records.values()):
            return 'camera_id_case_variant'
        if value == info.get('dev_id'):
            return 'hub_id'
        try:
            mac = normalize_mac(value)
            return 'camera_mac' if mac in records else 'hub_mac' if info.get('mac') and mac == normalize_mac(info['mac']) else 'other_mac'
        except ValueError:
            return 'opaque'
    channel = query.get('channels', query.get('channel'))
    values = channel if isinstance(channel, list) else [channel]
    safe_channel = channel if len(values) <= 8 and all(type(v) is int and 0 <= v < 32 for v in values) else type(channel).__name__
    LOG.info('PLAYBACK routing uri_kinds=%s body_kinds=%s channels=%s',
             {key[:40]: [kind(value) for value in values] for key, values in fields.items()},
             {key: kind(query[key]) for key in ('camera_mac', 'child_device_mac', 'child_device_id', 'player_id', 'client_id') if key in query},
             safe_channel)
    selectors = {}
    for key in ("camera_mac", "child_device_mac"):
        if key in fields:
            if len(fields[key]) != 1:
                raise ValueError("Ambiguous URI camera selector")
            selectors[key] = normalize_mac(fields[key][0])
    if "deviceId" in fields:
        if len(fields["deviceId"]) != 1:
            raise ValueError("Ambiguous URI device selector")
        storage = handler.server.playback.storage
        with storage.lock:
            if any(record.get("device_id") == fields["deviceId"][0] for record in storage.devices.values()):
                selectors["child_device_id"] = fields["deviceId"][0]
    for key, value in selectors.items():
        if query.get(key) and (normalize_mac(query[key]) if key.endswith("mac") else query[key]) != value:
            raise ValueError("Conflicting URI camera selector")
    return {**selectors, **query}


class MediaAuth:
    def __init__(self):
        self.lock = threading.Lock()
        self.challenges = {}
        self.slots = threading.BoundedSemaphore(2)

    def challenge(self, peer, password_hash):
        nonce, opaque = secrets.token_hex(16), secrets.token_hex(16)
        with self.lock:
            self.challenges = {key: value for key, value in self.challenges.items() if value[2] > time.monotonic()}
            if len(self.challenges) >= 128:
                self.challenges.pop(next(iter(self.challenges)))
            self.challenges[nonce] = (peer, opaque, time.monotonic() + 60, password_hash)
        return ('Digest realm="Tapo Hub",nonce="' + nonce + '",opaque="' + opaque
                + '",algorithm=MD5,qop="auth",encrypt_type="3"')

    def verify(self, authorization, peer, password_hash, request_uri="/stream"):
        if not authorization.startswith("Digest ") or len(authorization) > 2048:
            return False
        try:
            fields = parse_keqv_list(parse_http_list(authorization[7:]))
            with self.lock:
                challenge = self.challenges.pop(fields.get("nonce"), None)
            if not challenge or challenge[0] != peer or challenge[2] <= time.monotonic() or challenge[3] != password_hash:
                LOG.info("PLAYBACK digest rejected challenge_present=%s peer_matches=%s", bool(challenge),
                         bool(challenge and challenge[0] == peer))
                return False
            checks = {"admin": fields.get("username") == "admin", "realm": fields.get("realm") == "Tapo Hub",
                      "uri": fields.get("uri") in ("/stream", request_uri), "qop": fields.get("qop") == "auth",
                      "nc": fields.get("nc") == "00000001", "opaque": fields.get("opaque") == challenge[1],
                      "cnonce": bool(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", fields.get("cnonce", "")))}
            if not all(checks.values()):
                LOG.info("PLAYBACK digest field checks=%s fields=%s", json.dumps(checks), sorted(fields))
                return False
            def md5(value):
                return hashlib.md5(value.encode()).hexdigest()
            expected = md5(":".join((md5("admin:Tapo Hub:" + password_hash), fields["nonce"],
                                     fields["nc"], fields["cnonce"], "auth", md5("POST:" + fields["uri"]))))
            matched = hmac.compare_digest(expected, fields.get("response", ""))
            if not matched:
                LOG.info("PLAYBACK digest rejected proof_mismatch=True response_length=%d", len(fields.get("response", "")))
            return matched
        except (ValueError, TypeError, KeyError):
            return False


def encrypt(data, nonce, password_hash):
    key = hashlib.md5((nonce + ":" + password_hash).encode()).digest()
    iv = hashlib.md5(("admin:" + nonce).encode()).digest()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return cipher.update(padded) + cipher.finalize()


def part(handler, data, content_type="application/json", session=None, sequence=None, encrypted=False, timestamp=None):
    fields = {"Content-Type": content_type, "Content-Length": str(len(data)), "X-If-Encrypt": str(int(encrypted))}
    if session is not None:
        fields["X-Session-Id"] = str(session)
    if sequence is not None:
        fields["X-Data-Sequence"] = str(sequence)
    if timestamp is not None:
        fields["Snapshot_ts"] = str(timestamp)
    handler.wfile.write(getattr(handler, "playback_boundary", b"--" + BOUNDARY) + b"\r\n"
                        + "".join(k + ": " + v + "\r\n" for k, v in fields.items()).encode()
                        + b"\r\n" + data + b"\r\n")
    handler.wfile.flush()


def serve_playback(handler):
    handler.protocol_version = "HTTP/1.1"
    handler.connection.settimeout(10)
    password_hash = handler.server.setup.auth.password_hash
    auth = handler.server.media_auth
    authorization = handler.headers.get("Authorization", "")
    if not auth.verify(authorization, handler.client_address[0], password_hash, handler.path):
        LOG.info("PLAYBACK auth peer=%s authorization_present=%s result=challenge", handler.client_address[0], bool(authorization))
        handler.send_response(401)
        handler.send_header("WWW-Authenticate", auth.challenge(handler.client_address[0], password_hash))
        handler.send_header("Content-Length", "0")
        handler.end_headers()
        # The native client retries authentication on this same connection.
        handler.close_connection = bool(authorization)
        return
    LOG.info("PLAYBACK auth peer=%s result=accepted", handler.client_address[0])
    if not auth.slots.acquire(blocking=False):
        handler.close_connection = True
        handler.send_error(503)
        return
    process = None
    started = False
    stage = "http_framing"
    leases = ExitStack()
    try:
        content_type = handler.headers.get("Content-Type", "")
        match = re.fullmatch(r'multipart/mixed;\s*boundary="?([A-Za-z0-9_-]{1,64})"?', content_type)
        if not match or handler.headers.get("Transfer-Encoding"):
            raise ValueError("Unsupported playback framing")
        nonce = secrets.token_hex(16)
        # Streamd's native handshake is HTTP/1.0 with an indefinite multipart body.
        handler.protocol_version = "HTTP/1.0"
        handler.send_response(200)
        handler.send_header("Content-Type", "multipart/mixed;boundary=" + BOUNDARY.decode())
        handler.send_header("Pragma", "no-cache")
        handler.send_header("Cache-Control", "no-cache")
        handler.send_header("Key-Exchange", 'cipher="AES_128_CBC" username="admin" padding="PKCS7_16" '
                            'algorithm="MD5" encrypt_type="3" nonce="' + nonce + '"')
        handler.send_header("Connection", "close")
        handler.end_headers()
        started = True
        advertised_boundary = match[1].encode()
        stage = "command_boundary"
        line = handler.rfile.readline(129)
        if line == b"\r\n":
            line = handler.rfile.readline(129)
        if line not in (advertised_boundary + b"\r\n", b"--" + advertised_boundary + b"\r\n"):
            LOG.info("PLAYBACK boundary rejected bytes=%d advertised_bytes=%d contains_advertised=%s",
                     len(line), len(advertised_boundary), advertised_boundary in line)
            raise ValueError("Invalid playback command boundary")
        native_boundary = line == advertised_boundary + b"\r\n"
        handler.playback_boundary = BOUNDARY if native_boundary else b"--" + BOUNDARY
        LOG.info("PLAYBACK framing native_boundary=%s", native_boundary)
        stage = "command_headers"
        fields = headers(handler.rfile)
        length = integer(fields.get("content-length"), 1, 16384)
        if (fields.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                or fields.get("x-if-encrypt", "0") not in ("0", "1")):
            raise ValueError("Unsupported playback command encoding")
        stage = "command_body"
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Truncated playback command")
        if fields.get("x-if-encrypt") == "1":
            stage = "command_decryption"
            raw = decrypt_media(raw, 'username="admin" nonce="' + nonce + '"', password_hash)
        stage = "command_json"
        request = json.loads(raw)
        if not isinstance(request, dict) or not isinstance(request.get("params"), dict):
            raise ValueError("Invalid playback command")
        seq = integer(request["seq"], high=2_147_483_647)
        stage = "command_schema"
        params = request["params"]
        LOG.info("PLAYBACK command type=%s method=%s params_fields=%s",
                 request.get("type") if request.get("type") in ("request", "response", "notification") else "other",
                 params.get("method") if params.get("method") in ("get", "set", "do") else "other",
                 sorted(str(key)[:64] for key in params)[:24])
        query = params.get("playback", params.get("download", params.get("image")))
        if request.get("type") != "request" or params.get("method") != "get" or not isinstance(query, dict):
            raise ValueError("Unsupported playback command")
        # Log field names only; credentials, identifiers and timestamps stay private.
        LOG.info("PLAYBACK media request fields=%s", sorted(str(key)[:64] for key in query)[:24])
        session = secrets.randbelow(2_000_000_000) + 1
        leases.enter_context(activity())
        if "image" in params:
            if "playback" in params or "download" in params or getattr(handler.server, "faces", None) is None:
                raise ValueError("Face photo backend unavailable")
            stage = "face_photo_selection"
            images = handler.server.faces.media_photos(query)
            part(handler, json.dumps({"type": "response", "seq": seq, "params": {
                "error_code": 0, "session_id": str(session),
                "face_status": ["exist" if image is not None else "error" for _, image in images]}}).encode())
            for index, (key, image) in enumerate(images, 1):
                if image is None:
                    continue
                part(handler, encrypt(image, nonce, password_hash), "image/jpeg", session, index, True)
                part(handler, json.dumps({"type": "notification", "params": {"event_type": "stream_status",
                    "status": "image_ended", "face_id": key, "session_id": str(session)}}).encode(), session=session)
            part(handler, json.dumps({"type": "notification", "params": {"event_type": "stream_status",
                "status": "finished", "session_id": str(session)}}).encode(), session=session)
            LOG.info("FACE photo stream completed images=%d missing=%d", len(images),
                     sum(image is None for _, image in images))
            return
        query = routed_query(handler, query)
        if "download" in params:
            if "playback" in params or query.get("media_type") not in (2, "2"):
                raise ValueError("Only recorded thumbnail downloads are supported")
            stage = "thumbnail_selection"
            LOG.info("PLAYBACK thumbnail filters=%s", json.dumps(filter_summary(query), separators=(",", ":")))
            row, image = handler.server.playback.thumbnail(query)
            part(handler, json.dumps({"type": "response", "seq": seq,
                "params": {"error_code": 0, "session_id": str(session)}}).encode())
            part(handler, encrypt(image, nonce, password_hash), "image/jpeg", session, 1, True, row["start"])
            part(handler, json.dumps({"type": "notification", "params": {"event_type": "stream_status",
                "status": "finished", "session_id": str(session)}}).encode(), session=session)
            LOG.info("PLAYBACK thumbnail finished bytes=%d", len(image))
            return
        # shortcut: one clip/image per connection; add native batch/seek/stop commands when verified.
        if query.get("scale", "1/1") != "1/1":
            raise ValueError("Unsupported playback speed")
        stage = "recording_selection"
        LOG.info("PLAYBACK selection filters=%s", json.dumps(filter_summary(query), separators=(",", ":")))
        row, files, offset, duration = handler.server.playback.stream_files(query)
        source = ['-i', str(row['path'])]
        if len(files) > 1:
            manifest = leases.enter_context(tempfile.NamedTemporaryFile(mode='w', suffix='.concat',
                                           prefix='.playback-', dir=row['path'].parent))
            for item in files:
                value = str(item['path'])
                if '\n' in value or '\r' in value:
                    raise ValueError('Invalid playback path')
                manifest.write("file '" + value.replace("'", "'\\''") + "'\n")
                manifest.write('duration ' + str(item['duration']) + '\n')
            manifest.flush()
            source = ['-f', 'concat', '-safe', '0', '-i', manifest.name]
        stage = "media_remux"
        process = subprocess.Popen(["ffmpeg", "-v", "error", "-nostdin", "-re", "-ss", str(offset),
            *source, "-t", str(duration), "-map", "0:v:0", "-map", "0:a:0?",
            "-c", "copy", "-output_ts_offset", str(row["start"] + offset), "-f", "mpegts", "pipe:1"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        data = process.stdout.read(188 * 64)
        if not data or data[0] != 0x47:
            raise ValueError("Playback produced no transport stream")
        part(handler, json.dumps({"type": "response", "seq": seq,
                                  "params": {"error_code": 0, "session_id": str(session)}}).encode())
        deadline, count, total = time.monotonic() + 140, 0, 0
        while data:
            if time.monotonic() > deadline or total + len(data) > 30_000_000:
                raise ValueError("Playback exceeded bounds")
            total += len(data)
            count += 1
            part(handler, encrypt(data, nonce, password_hash), "video/mp2t", session, count, True)
            data = process.stdout.read(188 * 64)
        if process.wait(timeout=5) != 0:
            raise ValueError("Playback remux failed")
        part(handler, json.dumps({"type": "notification", "params": {
            "event_type": "stream_status", "status": "finished", "session_id": str(session)}}).encode(), session=session)
        LOG.info("PLAYBACK media finished bytes=%d", total)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        LOG.info("PLAYBACK media rejected stage=%s reason=%s", stage, type(error).__name__)
        # A rejected command must never pretend to be a valid media session.
        try:
            if started:
                part(handler, json.dumps({"type": "response", "seq": locals().get("seq", 0),
                                          "params": {"error_code": -40209}}).encode())
            else:
                handler.send_error(400)
        except OSError:
            pass
    finally:
        handler.close_connection = True
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
        finally:
            auth.slots.release()
            leases.close()


class PlaybackMedia(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/stream":
            self.send_error(404)
            return
        serve_playback(self)

    def log_message(self, *args):
        pass
