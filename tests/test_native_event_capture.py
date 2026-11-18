import io
import json
from pathlib import Path
import tempfile
import subprocess
import threading
import socket
import struct
import time
from http.server import ThreadingHTTPServer
from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from native_event_capture import NativeEventCapture, copy_body, tcp_summary
from hub_lab import Diagnostics, NativeMedia
from camera_media import headers


class NativeEventCaptureTests(unittest.TestCase):
    def test_stream_sender_waiting_for_admission_can_finish_and_reuse_connection(self):
        self.record['ip_addr'] = '127.0.0.1'
        first = (b'--data-boundary--\r\nContent-Type: video/x-h264\r\n'
                 b'Content-Length: 32\r\nX-Decrypt-Length: 16\r\n\r\n' + b'x'*16)
        tail = b'x'*16 + b'\r\n--data-boundary----\r\n'
        completed = threading.Event()
        def publish(path, metadata, *_):
            self.assertEqual(Path(path).read_bytes(), first+tail)
            self.assertTrue(metadata['transfer_complete'])
            self.assertTrue(metadata['ready_reply_sent'])
            completed.set()
            return {'bytes': len(first+tail)}
        server = ThreadingHTTPServer(('127.0.0.1', 0), NativeMedia)
        server.native_event_capture = self.receiver
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with patch('native_event_capture.STORE', Path(self.directory.name)), \
                patch('native_event_capture.disk_info', return_value={'status': 'normal'}), \
                patch('native_event_capture.os.statvfs', return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch('native_event_capture.save_event', side_effect=publish) as publisher:
            try:
                with socket.create_connection(server.server_address, timeout=2) as client, client.makefile('rb') as response:
                    for event in ('123', '124'):
                        completed.clear()
                        publisher.reset_mock()
                        request = ('POST /stream/alarm_streaming HTTP/1.1\r\nHost: localhost\r\n'
                                   'Device-Mac: '+self.mac+'\r\nEvent-Id: '+event+'\r\nX-Nonce: '+'a'*32+'\r\n'
                                   'Transfer-Encoding: chunked\r\nContent-Type: multipart/x-mixed-replace;boundary=data-boundary--\r\n\r\n').encode()
                        client.sendall(request + format(len(first), 'x').encode()+b'\r\n'+first+b'\r\n')
                        # A camera may wait here: no final bytes/terminating HTTP chunk were sent yet.
                        self.assertIn(b'200 OK', response.readline())
                        reply = headers(response)
                        self.assertEqual(reply['connection'], 'keep-alive')
                        self.assertEqual(reply['content-length'], '0')
                        publisher.assert_not_called()
                        client.sendall(format(len(tail), 'x').encode()+b'\r\n'+tail+b'\r\n0\r\n\r\n')
                        self.assertTrue(completed.wait(2))
                        publisher.assert_called_once()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_stream_ready_does_not_publish_an_interrupted_upload(self):
        self.handler.path = '/stream/alarm_streaming'
        first = (b'--data-boundary--\r\nContent-Type: video/x-h264\r\n'
                 b'Content-Length: 32\r\n\r\n' + b'x'*16)
        self.handler.headers.pop('Content-Length')
        self.handler.headers.update({'Transfer-Encoding': 'chunked',
            'Content-Type': 'multipart/x-mixed-replace;boundary=data-boundary--'})
        self.handler.rfile = io.BytesIO(format(len(first),'x').encode()+b'\r\n'+first+b'\r\n')
        self.handler.native_stream_ready = Mock()
        with self.assertRaises(ValueError):
            self.receive()
        self.handler.native_stream_ready.assert_called_once()
        self.assertEqual(list(Path(self.directory.name).glob('events/*.mp4')), [])

    def test_invalid_first_frame_never_receives_stream_admission(self):
        self.handler.path = '/stream/alarm_streaming'
        first = b'--data-boundary--\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nwire'
        self.handler.headers.pop('Content-Length')
        self.handler.headers.update({'Transfer-Encoding':'chunked',
            'Content-Type':'multipart/x-mixed-replace;boundary=data-boundary--'})
        self.handler.rfile = io.BytesIO(format(len(first),'x').encode()+b'\r\n'+first+b'\r\n0\r\n\r\n')
        self.handler.native_stream_ready = Mock()
        with self.assertRaises(ValueError):
            self.receive()
        self.handler.native_stream_ready.assert_not_called()

    def test_tcp_diagnostics_read_only_fixed_counters_and_ignore_unsupported_sockets(self):
        data = bytearray(144)
        data[0] = 1
        for offset, value in ((52, 20000), (68, 1200), (100, 3), (140, 90)):
            struct.pack_into("=I", data, offset, value)
        struct.pack_into("=Q", data, 128, 123456)
        connection = Mock()
        connection.getsockopt.return_value = bytes(data)
        self.assertEqual(tcp_summary(connection), {"state": 1, "last_data_received_ms": 20000,
            "rtt_us": 1200, "server_total_retransmits": 3, "received_bytes": 123456,
            "received_segments": 90})
        connection.getsockopt.return_value = bytes(data[:104])
        self.assertNotIn("received_bytes", tcp_summary(connection))
        connection.getsockopt.return_value = b"short"
        self.assertEqual(tcp_summary(connection), {})
        connection.getsockopt.side_effect = OSError("not a TCP socket")
        self.assertEqual(tcp_summary(connection), {})

    @unittest.skipUnless(hasattr(socket, "TCP_INFO"), "Linux TCP_INFO required")
    def test_tcp_diagnostics_on_real_loopback_connection(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname()) as sender:
                connection, _ = listener.accept()
                with connection:
                    sender.sendall(b"owned-test")
                    self.assertEqual(connection.recv(10), b"owned-test")
                    summary = tcp_summary(connection)
                    self.assertEqual(summary["state"], 1)
                    self.assertGreaterEqual(summary["received_bytes"], 10)

    def test_native_media_listener_only_routes_upload_endpoints(self):
        handler = object.__new__(NativeMedia)
        handler.send_error = Mock()
        with patch.object(Diagnostics, "do_POST") as upload:
            handler.path = "/"
            handler.do_POST()
            handler.send_error.assert_called_once_with(404)
            upload.assert_not_called()
            handler.path = "/stream/alarm_snapshot"
            handler.do_POST()
            upload.assert_called_once_with()

    def test_http_success_requires_validated_media(self):
        for success in (True, False):
            with self.subTest(success=success):
                handler = object.__new__(NativeMedia)
                handler.path = "/stream/alarm_snapshot"
                handler.headers = {}
                receiver = Mock()
                if success:
                    receiver.receive.return_value = {"endpoint": handler.path, "bytes": 4}
                else:
                    receiver.receive.side_effect = ValueError("Invalid native JPEG framing")
                handler.server = SimpleNamespace(native_event_capture=receiver)
                for name in ("send_error", "send_response", "send_header", "end_headers"):
                    setattr(handler, name, Mock())
                handler.do_POST()
                if success:
                    handler.send_response.assert_called_once_with(200)
                    handler.send_error.assert_not_called()
                else:
                    handler.send_error.assert_called_once_with(503, "Native event could not be validated")
                    handler.send_response.assert_not_called()

    def test_validation_failure_after_stream_admission_closes_without_a_second_reply(self):
        handler = object.__new__(NativeMedia)
        handler.path = '/stream/alarm_streaming'
        handler.headers = {}
        handler.wfile = io.BytesIO()
        for name in ('send_error', 'send_response', 'send_response_only', 'send_header', 'end_headers'):
            setattr(handler, name, Mock())
        def receive(request):
            request.native_stream_ready()
            raise ValueError('Incomplete event after admission')
        handler.server = SimpleNamespace(native_event_capture=SimpleNamespace(receive=receive))
        handler.do_POST()
        handler.send_response_only.assert_called_once_with(200)
        handler.send_error.assert_not_called()
        handler.send_response.assert_not_called()
        self.assertTrue(handler.close_connection)

    def setUp(self):
        for name, value in (("activity", nullcontext()), ("cleanup", None)):
            item = patch("native_event_capture." + name, side_effect=(lambda: nullcontext()) if name == "activity" else None,
                         return_value=value)
            item.start()
            self.addCleanup(item.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.mac = "10:00:00:00:00:02"
        self.record = {"device_model": "TD21", "ip_addr": "10.23.0.52",
                       "hub_storage_enabled": True, "recording_mode": "persistent_native", "registered_at": time.time()-3600}
        self.storage = SimpleNamespace(lock=threading.Lock(),
                                       devices={self.mac: self.record}, setup=SimpleNamespace(auth=SimpleNamespace(password_hash="A"*64)))
        self.receiver = NativeEventCapture(self.storage)
        self.handler = SimpleNamespace(path="/stream/alarm_snapshot", client_address=("10.23.0.52", 12345),
            headers={"Device-Mac": self.mac, "Event-Id": "123", "X-Nonce": "a"*32, "Content-Length": "4",
                     "Content-Type": "image/jpeg", "X-Dev-Token": "must-not-be-saved"},
            rfile=io.BytesIO(b"wire"), connection=Mock())

    def save(self, body, metadata, password, mac):
        self.assertEqual(Path(body).stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(body).read_bytes(), b"wire")
        self.assertNotIn("must-not-be-saved", json.dumps(metadata))
        return {"path": "validated.jpg", "bytes": 4}

    def receive(self):
        with patch("native_event_capture.STORE", Path(self.directory.name)), \
                patch("native_event_capture.disk_info", return_value={"status": "normal"}), \
                patch("native_event_capture.os.statvfs", return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch("native_event_capture.save_event", side_effect=self.save):
            return self.receiver.receive(self.handler)

    def test_private_upload_is_passed_to_validator_and_partial_is_removed(self):
        result = self.receive()
        self.assertEqual(result["recording"]["path"], "validated.jpg")
        self.assertEqual(list(Path(self.directory.name).glob("native-captures/*")), [])

    def test_one_camera_busy_does_not_block_the_other_camera_upload(self):
        busy = threading.Lock()
        busy.acquire()
        self.receiver.locks[(self.mac, self.handler.path)] = busy
        with self.assertRaises(ValueError):
            self.receive()
        other = '10:00:00:00:00:04'
        self.storage.devices[other] = {**self.record, 'device_model': 'C400',
            'hardware_version': '2.0', 'ip_addr': '10.23.0.78'}
        self.handler.headers['Device-Mac'] = other
        self.handler.client_address = ('10.23.0.78', 12345)
        self.assertEqual(self.receive()['recording']['path'], 'validated.jpg')
        self.assertTrue(busy.locked())
        busy.release()

    def test_wrong_peer_deferred_models_and_unverified_hardware_cannot_upload(self):
        for key, value in (("device_model", "TC70"), ("device_model", "C400"),
                           ("ip_addr", "10.23.0.60"), ("recording_mode", "bounded_event_observation"),
                           ("hub_storage_enabled", False)):
            with self.subTest(key=key, value=value):
                old = self.record[key]
                self.record[key] = value
                with self.assertRaises(ValueError):
                    self.receive()
                self.record[key] = old
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])

    def test_missing_mount_never_writes_to_root_disk(self):
        with patch("native_event_capture.disk_info", return_value={"status": "offline"}):
            with self.assertRaises(ValueError):
                self.receiver.receive(self.handler)

    def test_truncation_removes_partial_evidence(self):
        self.handler.headers["Content-Length"] = "5"
        with self.assertRaises(ValueError):
            self.receive()
        self.assertEqual(list(Path(self.directory.name).glob("native-captures/*")), [])

    def test_complete_failed_upload_is_retained_privately_for_replay(self):
        with patch("native_event_capture.STORE", Path(self.directory.name)), \
                patch("native_event_capture.disk_info", return_value={"status": "normal"}), \
                patch("native_event_capture.os.path.ismount", return_value=True), \
                patch("native_event_capture.os.statvfs", return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch("native_event_capture.save_event", side_effect=subprocess.CalledProcessError(1, "ffmpeg", stderr=b"codec failure")):
            with self.assertRaises(subprocess.CalledProcessError):
                self.receiver.receive(self.handler)
        files = list(Path(self.directory.name).glob("failed-uploads/td21/*.wire"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), b"wire")
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        metadata = Path(str(files[0]) + ".json")
        self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(metadata.read_text())["private_codec_error"], "codec failure")
        self.assertEqual(list(Path(self.directory.name).glob("native-captures/*.partial")), [])

    def test_c400_failure_evidence_is_not_blocked_by_full_td21_quarantine(self):
        directory = Path(self.directory.name)/'failed-uploads'
        directory.mkdir()
        for number in range(8):
            (directory/('failed-'+str(number)+'.wire')).write_bytes(b'older TD21 diagnostic')
        other = '10:00:00:00:00:04'
        self.storage.devices[other] = {**self.record, 'device_model': 'C400',
            'hardware_version': '2.0', 'ip_addr': '10.23.0.78'}
        self.handler.headers['Device-Mac'] = other
        self.handler.client_address = ('10.23.0.78', 12345)
        with patch('native_event_capture.STORE', Path(self.directory.name)), \
                patch('native_event_capture.disk_info', return_value={'status': 'normal'}), \
                patch('native_event_capture.os.path.ismount', return_value=True), \
                patch('native_event_capture.os.statvfs', return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch('native_event_capture.save_event', side_effect=ValueError('Unsupported camera format')):
            for number in range(10):
                self.handler.headers['Event-Id'] = str(number)
                self.handler.rfile = io.BytesIO(b'wire')
                with self.assertRaises(ValueError):
                    self.receiver.receive(self.handler)
        self.assertEqual(len(list(directory.glob('*.wire'))), 8)
        files = list((directory/'c400').glob('*.wire'))
        self.assertEqual(len(files), 8)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(Path(str(files[0])+'.json').read_text())['camera_mac'], other)

    def test_retry_keeps_the_largest_private_capture_for_the_same_event(self):
        metadata = {'event_id': '12345', 'endpoint': '/stream/alarm_streaming', 'transfer_complete': False}
        root = Path(self.directory.name)
        with patch('native_event_capture.STORE', root), \
                patch('native_event_capture.disk_info', return_value={'status': 'normal'}), \
                patch('native_event_capture.os.path.ismount', return_value=True):
            for payload, expected in ((b'ab', True), (b'abcd', True), (b'a', False)):
                partial = root/'retry.partial'
                partial.write_bytes(payload)
                partial.chmod(0o600)
                self.assertEqual(self.receiver.retain_failure(partial, metadata, self.mac, TimeoutError()), expected)
        files = list((root/'failed-uploads'/'td21').glob('*.wire'))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), b'abcd')
        self.assertEqual(json.loads(Path(str(files[0])+'.json').read_text())['bytes'], 4)

    def test_incomplete_upload_is_private_bounded_evidence_never_a_recording(self):
        legacy = Path(self.directory.name)/'failed-uploads'
        legacy.mkdir()
        for number in range(8):
            (legacy/('legacy-'+str(number)+'.wire')).write_bytes(b'preserved older diagnostic')
        self.handler.headers.pop("Content-Length")
        self.handler.headers["Transfer-Encoding"] = "chunked"
        self.handler.path = "/stream/alarm_streaming"
        class StalledStream(io.BytesIO):
            def read1(self, *args):
                if self.tell() == len(self.getvalue()):
                    raise TimeoutError("idle transfer")
                return super().read1(*args)
        with patch("native_event_capture.STORE", Path(self.directory.name)), \
                patch("native_event_capture.disk_info", return_value={"status": "normal"}), \
                patch("native_event_capture.os.path.ismount", return_value=True), \
                patch("native_event_capture.os.statvfs", return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch("native_event_capture.save_event") as save:
            for event in range(10):
                self.handler.headers["Event-Id"] = str(event)
                self.handler.rfile = StalledStream(b"4\r\nwire\r\n")
                with self.assertRaises(TimeoutError):
                    self.receiver.receive(self.handler)
            save.assert_not_called()
        files = list(Path(self.directory.name).glob("failed-uploads/td21/*.wire"))
        self.assertEqual(len(files), 8)
        self.assertEqual({json.loads(Path(str(p)+'.json').read_text())['event_id'] for p in files},
                         {str(i) for i in range(2, 10)})
        self.assertEqual(len(list(legacy.glob('*.wire'))), 8)
        self.assertTrue(all(p.read_bytes() == b'preserved older diagnostic' for p in legacy.glob('*.wire')))
        self.assertEqual(files[0].read_bytes(), b"wire")
        details = json.loads(Path(str(files[0]) + ".json").read_text())
        self.assertEqual(details["stage"], "transfer")
        self.assertEqual(details["transfer_stage"], "chunk_header")
        self.assertFalse(details["transfer_complete"])
        self.assertNotIn("must-not-be-saved", json.dumps(details))
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(Path(self.directory.name).glob("native-captures/*.partial")), [])
        self.assertTrue(self.record["hub_storage_enabled"])

    def test_snapshot_and_stream_have_separate_capture_slots(self):
        self.receive()
        self.handler.path = "/stream/alarm_streaming"
        self.handler.rfile = io.BytesIO(b"wire")
        self.assertEqual(self.receive()["bytes"], 4)

    def test_persistent_receiver_accepts_more_than_four_events_and_preserves_disk_margin(self):
        for event in range(5):
            self.handler.headers["Event-Id"] = str(event)
            self.handler.rfile = io.BytesIO(b"wire")
            self.receive()
        receiver = NativeEventCapture(self.storage)
        with patch("native_event_capture.disk_info", return_value={"status": "normal"}), \
                patch("native_event_capture.os.statvfs", return_value=SimpleNamespace(f_bavail=1, f_frsize=4096)):
            with self.assertRaises(ValueError):
                receiver.receive(self.handler)

    def test_http_chunks_are_decoded_and_malformed_oversized_or_late_uploads_fail(self):
        output = io.BytesIO()
        self.assertEqual(copy_body(io.BytesIO(b"2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n"),
                                   output, None, True, 4, time.monotonic()+5), 4)
        self.assertEqual(output.getvalue(), b"abcd")
        for payload in (b"5\r\nabcde\r\n0\r\n\r\n", b"bad\n", b"2\r\na", b"0\r\nX: y\r\n"):
            with self.assertRaises(ValueError):
                copy_body(io.BytesIO(payload), io.BytesIO(), None, True, 4, time.monotonic()+5)
        with self.assertRaises(ValueError):
            copy_body(io.BytesIO(b"a"), io.BytesIO(), 1, False, 4, time.monotonic()-1)

    def test_weak_wifi_pause_over_twenty_seconds_is_tolerated_with_a_total_deadline(self):
        clock, timeouts = [0], []
        class PausedStream(io.BytesIO):
            def read1(self, size):
                clock[0] += 45
                if timeouts[-1] < 45:
                    raise TimeoutError('bounded simulated pause')
                return super().read1(size)
        with patch('native_event_capture.time.monotonic', side_effect=lambda: clock[0]):
            output = io.BytesIO()
            self.assertEqual(copy_body(PausedStream(b'wire'), output, 4, False, 4, 240,
                                       set_timeout=timeouts.append), 4)
            self.assertEqual(output.getvalue(), b'wire')
            self.assertLessEqual(max(timeouts), 60)
            clock[0] = 0
            with self.assertRaises(TimeoutError):
                copy_body(PausedStream(b'wire'), io.BytesIO(), 4, False, 4, 30,
                          set_timeout=timeouts.append)

    def test_total_deadline_applies_even_to_a_dripping_chunk_header(self):
        clock = [0]
        class DrippingStream(io.BytesIO):
            def read1(self, size):
                clock[0] += 0.5
                return super().read1(min(size, 1))
        stream = DrippingStream(b"00000004\r\nwire\r\n0\r\n\r\n")
        timeouts = []
        with patch("native_event_capture.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ValueError, "time limit"):
                copy_body(stream, io.BytesIO(), None, True, 100, 2, set_timeout=timeouts.append)
        self.assertLessEqual(stream.tell(), 4)
        self.assertLessEqual(max(timeouts), 2)

    def test_reads_preserve_partial_body_progress_before_a_timeout(self):
        class InterruptedStream(io.BytesIO):
            def read1(self, size):
                if self.tell() == 2:
                    raise TimeoutError("lost connection")
                return super().read1(min(size, 2))
        output, progress = io.BytesIO(), {}
        with self.assertRaises(TimeoutError):
            copy_body(InterruptedStream(b"wire"), output, 4, False, 4, time.monotonic()+10, progress)
        self.assertEqual(output.getvalue(), b"wi")
        self.assertEqual(progress["chunk_remaining"], 2)
        self.assertEqual(progress["received_body_bytes"], 2)
        self.assertEqual(progress["timeout_kind"], "deadline")
        self.assertGreaterEqual(progress["transfer_elapsed_seconds"], 0)

    def test_timeout_diagnostics_distinguish_idle_from_total_deadline(self):
        class StalledStream(io.BytesIO):
            def read1(self, size):
                clock[0] += 20
                raise TimeoutError()
        clock, progress = [0], {}
        with patch("native_event_capture.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(TimeoutError):
                copy_body(StalledStream(), io.BytesIO(), 4, False, 4, 125, progress)
        self.assertEqual(progress["timeout_kind"], "idle")
        self.assertEqual(progress["last_data_age_seconds"], 20)
        self.assertEqual(progress["transfer_elapsed_seconds"], 20)


if __name__ == "__main__":
    unittest.main()
