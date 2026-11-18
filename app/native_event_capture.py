"""Receive and validate bounded native camera uploads on the isolated store."""
import os
import hashlib
import io
import json
import logging
from pathlib import Path
import re
import socket
import struct
import tempfile
import threading
import time
from contextlib import ExitStack

from camera_media import STORE
from camera_media import headers
from camera_registry import normalize_mac, camera_supported
from storage_status import disk_info
from native_recordings import save_event
from recording_retention import activity, cleanup, LOW_FREE

PATHS = {"/stream/alarm_snapshot": 2_000_000, "/stream/alarm_streaming": 20_000_000}
IDLE_TIMEOUT = 60
TRANSFER_TIMEOUT = 240
LOG = logging.getLogger("tapo-hub-lab")


def tcp_summary(connection):
    """Linux TCP_INFO counters only; no addresses, headers or application bytes."""
    try:
        info = connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 144)
    except (OSError, AttributeError):
        return {}
    if not isinstance(info, bytes) or len(info) < 104:
        return {}
    # Fixed Linux UAPI tcp_info prefix: include/uapi/linux/tcp.h.
    result = {"state": info[0], "last_data_received_ms": struct.unpack_from("=I", info, 52)[0],
              "rtt_us": struct.unpack_from("=I", info, 68)[0],
              "server_total_retransmits": struct.unpack_from("=I", info, 100)[0]}
    if len(info) >= 144:
        result.update(received_bytes=struct.unpack_from("=Q", info, 128)[0],
                      received_segments=struct.unpack_from("=I", info, 140)[0])
    return result


def copy_body(stream, output, length, chunked, limit, deadline, progress=None, set_timeout=None, on_data=None):
    """Preserve transfer-decoded bytes without interpreting unverified media frames."""
    started = last_data = time.monotonic()
    def read_piece(size):
        nonlocal last_data
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise ValueError("Native upload exceeded its time limit")
        if set_timeout is not None:
            set_timeout(min(IDLE_TIMEOUT, remaining_time))
        # Buffered read(n) can wait for n bytes despite progress; read1 returns each arrival.
        try:
            data = getattr(stream, "read1", stream.read)(size)
        except OSError as error:
            if progress is not None:
                now = time.monotonic()
                progress.update(transfer_elapsed_seconds=round(now - started, 3),
                                last_data_age_seconds=round(now - last_data, 3))
                if isinstance(error, TimeoutError):
                    progress['timeout_kind'] = 'deadline' if remaining_time <= IDLE_TIMEOUT else 'idle'
            raise
        if data:
            last_data = time.monotonic()
        elif progress is not None:
            now = time.monotonic()
            progress.update(peer_eof=True, transfer_elapsed_seconds=round(now-started, 3),
                            last_data_age_seconds=round(now-last_data, 3))
        return data

    def exact(size):
        result = bytearray()
        while len(result) < size:
            data = read_piece(size - len(result))
            if not data:
                break
            result.extend(data)
        return bytes(result)

    total = 0
    while True:
        if time.monotonic() > deadline:
            raise ValueError("Native upload exceeded its time limit")
        if chunked:
            if progress is not None:
                progress["transfer_stage"] = "chunk_header"
            line = bytearray()
            while len(line) < 129:
                char = read_piece(1)
                if not char:
                    break
                line.extend(char)
                if char == b"\n":
                    break
            if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}\r\n", line):
                if progress is not None:
                    progress.update(chunk_header_bytes=len(line), chunk_header_complete=line.endswith(b'\r\n'))
                raise ValueError("Invalid native HTTP chunk")
            size = int(line, 16)
            if size == 0:
                if exact(2) != b"\r\n":
                    raise ValueError("Unsupported native HTTP trailers")
                return total
        else:
            size = length
        if size < 0 or total + size > limit:
            raise ValueError("Native upload exceeded its size limit")
        remaining = size
        if progress is not None:
            progress.update(transfer_stage="body", chunk_size=size, chunk_remaining=remaining)
        while remaining:
            if time.monotonic() > deadline:
                raise ValueError("Native upload exceeded its time limit")
            data = read_piece(min(65536, remaining))
            if not data:
                raise ValueError("Truncated native upload")
            output.write(data)
            remaining -= len(data)
            total += len(data)
            if progress is not None:
                progress["chunk_remaining"] = remaining
                progress["received_body_bytes"] = total
            if on_data is not None:
                on_data(data)
        if not chunked:
            return total
        if progress is not None:
            progress["transfer_stage"] = "chunk_terminator"
        if exact(2) != b"\r\n":
            raise ValueError("Invalid native chunk terminator")


class NativeEventCapture:
    def __init__(self, storage):
        self.storage = storage
        self.locks = {}
        self.locks_lock = threading.Lock()
        self.failure_lock = threading.Lock()

    def retain_failure(self, body, metadata, mac, error):
        """Keep bounded private evidence so a natural event can be replayed without retriggering."""
        if not os.path.ismount(STORE) or disk_info()["status"] != "normal":
            return False
        with self.failure_lock:
            directory = STORE / "failed-uploads"
            model = self.storage.devices.get(mac, {}).get("device_model")
            if model in ("TD21", "C400"):
                directory = directory / model.lower()
                directory.parent.mkdir(mode=0o700, exist_ok=True)
            directory.mkdir(mode=0o700, exist_ok=True)
            key = hashlib.sha256((mac + ":" + metadata["event_id"] + ":" + metadata["endpoint"]
                                  + ":" + str(metadata.get("transfer_complete", True))).encode()).hexdigest()[:24]
            target = directory / ("failed-" + key + ".wire")
            if target.exists():
                if target.is_symlink() or Path(body).stat().st_size <= target.stat().st_size:
                    return False
            files = sorted(directory.glob('failed-*.wire'), key=lambda path: path.stat().st_mtime)
            if not target.exists() and len(files) >= 8:
                oldest = files[0]
                if oldest.is_symlink():
                    return False
                oldest.unlink()
                Path(str(oldest) + '.json').unlink(missing_ok=True)
            details = {**metadata, "camera_mac": mac, "error_type": type(error).__name__,
                       "bytes": Path(body).stat().st_size,
                       "stage": getattr(error, "media_stage", "decode_or_probe" if metadata.get("transfer_complete", True) else "transfer"),
                       "returncode": getattr(error, "returncode", None)}
            stderr = getattr(error, "stderr", None)
            if isinstance(stderr, bytes):
                details["private_codec_error"] = stderr[:4096].decode(errors="replace")
            fd, temporary = tempfile.mkstemp(dir=directory, prefix='.failure-')
            try:
                with os.fdopen(fd, "w") as stream:
                    json.dump(details, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(body, target)
                os.replace(temporary, str(target) + '.json')
            finally:
                Path(temporary).unlink(missing_ok=True)
            return True

    def receive(self, handler):
        """Save a complete native upload without changing the camera association."""
        mac = normalize_mac(handler.headers.get("Device-Mac"))
        with self.storage.lock:
            record = dict(self.storage.devices.get(mac, {}))
        if (handler.path not in PATHS or not camera_supported(record)
                or record.get("ip_addr") != handler.client_address[0]
                or not record.get("hub_storage_enabled") or record.get("recording_mode") != "persistent_native"):
            raise ValueError("No current authenticated camera registration")
        with self.locks_lock:
            capture_lock = self.locks.setdefault((mac, handler.path), threading.Lock())
        if not capture_lock.acquire(blocking=False):
            raise ValueError("Native capture already busy")
        partial = None
        metadata = None
        leases = ExitStack()
        try:
            event_id = handler.headers.get("Event-Id", "")
            if not re.fullmatch(r"[0-9]{1,20}", event_id):
                raise ValueError("Invalid native event identifier")
            nonce = handler.headers.get("X-Nonce", "")
            if not re.fullmatch(r"[0-9A-Fa-f]{32}", nonce):
                raise ValueError("Unsupported native nonce")
            transfer = handler.headers.get("Transfer-Encoding", "").lower()
            length_header = handler.headers.get("Content-Length")
            if transfer not in ("", "chunked") or (transfer and length_header is not None):
                raise ValueError("Ambiguous native transfer framing")
            if length_header is not None and not re.fullmatch(r"[0-9]{1,9}", length_header):
                raise ValueError("Invalid native upload length")
            length = int(length_header) if length_header is not None else None
            if not transfer and (length is None or not 0 < length <= PATHS[handler.path]):
                raise ValueError("Invalid native upload length")
            if disk_info()["status"] not in ("normal", "full"):
                raise ValueError("Dedicated recording mount unavailable")
            if os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize < LOW_FREE:
                cleanup()
            leases.enter_context(activity())
            if disk_info()["status"] != "normal" or os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize < PATHS[handler.path] + 100_000_000:
                raise ValueError("Dedicated recording mount unavailable")
            directory = STORE / "native-captures"
            directory.mkdir(mode=0o700, exist_ok=True)
            metadata = {"endpoint": handler.path, "event_id": event_id, "nonce": nonce,
                        "event_type": handler.headers.get("Event-Type", "")[:128],
                        "event_time": handler.headers.get("Event-Time", "")[:20],
                        "content_type": handler.headers.get("Content-Type", "")[:256],
                        "decrypt_length": handler.headers.get("X-Decrypt-Length", "")[:16],
                        "captured_at": time.time(), "validated_recording": False,
                        "transfer_complete": False, "expected_length": length, "chunked": transfer == "chunked"}
            ready = None
            if handler.path.endswith('alarm_streaming') and hasattr(handler, 'native_stream_ready'):
                match = re.fullmatch(r'multipart/x-mixed-replace;\s*boundary="?([A-Za-z0-9_-]{1,64})"?', metadata['content_type'])
                if not match:
                    raise ValueError('Unsupported native multipart type')
                boundary = b'--' + match[1].encode() + b'\r\n'
                prefix = bytearray()
                admission_started = time.monotonic()
                def ready(data):
                    if metadata.get('ready_reply_sent'):
                        return
                    prefix.extend(data[:max(0, 16512-len(prefix))])
                    while prefix.startswith(b'\r\n'):
                        del prefix[:2]
                    end = prefix.find(b'\r\n\r\n')
                    if end < 0:
                        if len(prefix) >= 16512:
                            raise ValueError('Native first frame headers too large')
                        return
                    if not prefix.startswith(boundary):
                        raise ValueError('Invalid native first frame boundary')
                    first = headers(io.BytesIO(prefix[len(boundary):end+4]))
                    if (first.get('content-type') not in ('video/x-h264', 'audio/g711u', 'audio/g711a')
                            or not re.fullmatch(r'[0-9]{1,7}', first.get('content-length', ''))
                            or not 0 < int(first['content-length']) <= 2_000_000):
                        raise ValueError('Invalid native first frame headers')
                    # Native H500 acknowledges stream admission at the first multipart header.
                    handler.native_stream_ready()
                    metadata['ready_reply_sent'] = True
                    metadata['ready_reply_elapsed_seconds'] = round(time.monotonic()-admission_started, 3)
                    LOG.info('UPLOAD stream admitted model=%s elapsed_seconds=%s',
                             record.get('device_model'), metadata['ready_reply_elapsed_seconds'])
                    prefix.clear()
            fd, partial = tempfile.mkstemp(dir=directory, prefix="native-event-", suffix=".partial")
            with os.fdopen(fd, "wb") as output:
                total = copy_body(handler.rfile, output, length, transfer == "chunked",
                                  PATHS[handler.path], time.monotonic() + TRANSFER_TIMEOUT,
                                  metadata, handler.connection.settimeout, ready)
                if not total:
                    raise ValueError("Empty native upload")
                output.flush()
                os.fsync(output.fileno())
            metadata.update(bytes=total, transfer_complete=True)
            saved = save_event(partial, metadata, self.storage.setup.auth.password_hash, mac)
            return {"endpoint": handler.path, "bytes": total, "recording": saved}
        except Exception as error:
            if metadata is not None:
                metadata["tcp_failure"] = tcp_summary(handler.connection)
                event_type = metadata.get('event_type', '')
                LOG.info("UPLOAD failure model=%s event_type=%s error=%s phase=%s bytes=%s elapsed=%s idle=%s timeout=%s",
                         record.get('device_model'), event_type if re.fullmatch(r'[A-Za-z0-9_]{1,16}', event_type) else 'other',
                         type(error).__name__, metadata.get("transfer_stage"),
                         metadata.get("received_body_bytes", 0), metadata.get("transfer_elapsed_seconds"),
                         metadata.get("last_data_age_seconds"), metadata.get("timeout_kind"))
                LOG.info("UPLOAD connection counters=%s", json.dumps(metadata["tcp_failure"], separators=(",", ":")))
            if partial is not None and metadata is not None:
                try:
                    if self.retain_failure(partial, metadata, mac, error):
                        partial = None
                except OSError:
                    pass
            raise
        finally:
            try:
                if partial is not None:
                    Path(partial).unlink(missing_ok=True)
            finally:
                capture_lock.release()
                leases.close()
