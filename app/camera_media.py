"""Bounded local preview recording; does not change camera storage settings."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import time
from urllib.request import parse_http_list, parse_keqv_list

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from camera_probe import CameraProbe, probe

from settings import STORE
MAX_BYTES = 20_000_000


def headers(stream):
    result, total = {}, 0
    for _ in range(64):
        line = stream.readline(4097)
        total += len(line)
        if not line or len(line) > 4096 or total > 16384:
            raise ValueError("Invalid media headers")
        if line == b"\r\n":
            return result
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("Invalid media header")
        result[name.decode("ascii").lower()] = value.strip().decode("ascii")
    raise ValueError("Too many media headers")


def digest(challenge, password_hash, cnonce):
    data = parse_keqv_list(parse_http_list(challenge.removeprefix("Digest ")))
    if data.get("encrypt_type") != "3" or data.get("algorithm", "MD5") != "MD5" or "auth" not in data.get("qop", "").split(","):
        raise ValueError("Media server does not support the saved SHA256 credential")
    def md5(value):
        return hashlib.md5(value.encode()).hexdigest()
    response = md5(":".join((md5("admin:" + data["realm"] + ":" + password_hash),
                              data["nonce"], "00000001", cnonce, "auth", md5("POST:/stream"))))
    fields = {"username": "admin", "realm": data["realm"], "nonce": data["nonce"],
              "uri": "/stream", "cnonce": cnonce, "response": response}
    if "opaque" in data:
        fields["opaque"] = data["opaque"]
    if any(not isinstance(v, str) or any(c in v for c in '\r\n"\\') for v in fields.values()):
        raise ValueError("Invalid media digest challenge")
    return "Digest " + ",".join(k + '="' + v + '"' for k, v in fields.items()) + ",algorithm=MD5,nc=00000001,qop=auth"


def decrypt_media(data, key_exchange, password_hash):
    exchange = dict(re.findall(r'(\w+)="?([^"\s]+)"?', key_exchange))
    username, nonce = exchange["username"].encode(), exchange["nonce"].encode()
    if username == b"none":
        raise ValueError("Camera requires an unavailable media-encryption key")
    key = hashlib.md5(nonce + b":" + password_hash.encode()).digest()
    iv = hashlib.md5(username + b":" + nonce).digest()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def preview_packets(address, password_hash):
    """One authenticated, continuous connection; caller closes the generator to stop."""
    CameraProbe(address, password_hash)
    request = (b"POST /stream HTTP/1.1\r\nContent-Type: multipart/mixed;boundary=--client-stream-boundary--\r\n"
               b"Connection: keep-alive\r\nContent-Length: -1\r\n")
    stage = "connection"
    try:
        with socket.create_connection((address, 8800), timeout=5) as connection, connection.makefile("rb") as stream:
            stage = "challenge"
            connection.sendall(request + b"\r\n")
            if b" 401 " not in stream.readline(4097):
                raise ValueError("Expected a media authentication challenge")
            challenge = headers(stream)
            length = int(challenge.get("content-length", "0"))
            if not 0 <= length <= 4096:
                raise ValueError("Invalid challenge length")
            stream.read(length)
            authorization = digest(challenge["www-authenticate"], password_hash, os.urandom(12).hex())
            stage = "authentication"
            connection.sendall(request + b"Authorization: " + authorization.encode() + b"\r\n\r\n")
            if b" 200 " not in stream.readline(4097):
                raise ValueError("Camera rejected media authentication")
            response = headers(stream)
            content_type = response.get("content-type", "")
            match = re.search(r'boundary="?([^";\s]+)', content_type)
            if not match:
                raise ValueError("Missing media boundary")
            boundary = match[1].encode()
            body = json.dumps({"type": "request", "seq": 1, "params": {"method": "get", "preview": {
                "audio": ["default"], "channels": [0], "resolutions": ["HD"]}}}).encode()
            connection.sendall(b"----client-stream-boundary--\r\nContent-Type: application/json\r\nContent-Length: "
                               + str(len(body)).encode() + b"\r\n\r\n" + body + b"\r\n")
            stage = "preview"
            last_media = time.monotonic()
            while True:
                if time.monotonic() - last_media > 10:
                    raise ValueError("Camera stopped sending video")
                line = stream.readline(4097)
                if not line or len(line) > 4096:
                    raise ValueError("Invalid media boundary")
                if boundary not in line:
                    continue
                part = headers(stream)
                length = int(part.get("content-length", "-1"))
                if not 0 <= length <= 2_000_000:
                    raise ValueError("Invalid media part length")
                data = stream.read(length)
                if len(data) != length:
                    raise ValueError("Truncated media part")
                if part.get("x-if-encrypt", "0") == "1":
                    data = decrypt_media(data, response.get("key-exchange", ""), password_hash)
                if part.get("content-type", "").split(";")[0] == "video/mp2t":
                    if not data or len(data) % 188 or any(data[i] != 0x47 for i in range(0, len(data), 188)):
                        raise ValueError("Invalid MPEG transport stream")
                    last_media = time.monotonic()
                    yield data
                elif part.get("content-type") == "application/json":
                    status = json.loads(data)
                    if status.get("params", {}).get("error_code", 0) != 0:
                        raise ValueError("Camera rejected the preview request")
    except TimeoutError:
        raise ValueError("Media timed out during " + stage) from None


def capture(address, password_hash, seconds=5):
    CameraProbe(address, password_hash)
    if type(seconds) is not int or not 1 <= seconds <= 15:
        raise ValueError("Test recording must be 1 to 15 seconds")
    if not os.path.ismount(STORE) or os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize < 100_000_000:
        raise ValueError("Dedicated recording mount is unavailable or low on space")
    fd, filename = tempfile.mkstemp(dir=STORE, prefix="preview-test-", suffix=".ts")
    packets = preview_packets(address, password_hash)
    started, total, parts = None, 0, 0
    try:
        with os.fdopen(fd, "wb") as output:
            for data in packets:
                if started is None:
                    started = time.monotonic()
                if total + len(data) > MAX_BYTES:
                    raise ValueError("Test recording exceeded its size limit")
                output.write(data)
                total += len(data)
                parts += 1
                if time.monotonic() - started >= seconds:
                    break
            if not total:
                raise ValueError("Camera sent no video")
            output.flush()
            os.fsync(output.fileno())
        return {"path": filename, "bytes": total, "parts": parts,
                "capture_seconds": round(time.monotonic() - started, 2)}
    except BaseException:
        Path(filename).unlink(missing_ok=True)
        raise
    finally:
        packets.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--seconds", type=int, default=5)
    args = parser.parse_args()
    try:
        state = "/var/lib/tapo-hub/state.json"
        camera = probe(args.mac, "/var/lib/tapo-hub/cameras.json", state)
        print(json.dumps(capture(camera["address"], json.loads(Path(state).read_text())["password_hash"], args.seconds)))
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"status": "capture_failed"}))
        raise SystemExit(1)
