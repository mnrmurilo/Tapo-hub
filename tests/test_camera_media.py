import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from camera_media import capture, digest, headers
from camera_probe import sha


class MediaTests(unittest.TestCase):
    def test_headers_are_bounded_and_case_insensitive(self):
        self.assertEqual(headers(io.BytesIO(b"Content-Length: 188\r\nX-If-Encrypt: 0\r\n\r\n")),
                         {"content-length": "188", "x-if-encrypt": "0"})
        for raw in (b"MissingColon\r\n\r\n", b"X: " + b"a" * 4096 + b"\r\n\r\n",
                    b"X: value\r\n" * 65, b""):
            with self.assertRaises(ValueError):
                headers(io.BytesIO(raw))

    def test_digest_rejects_other_prehash_and_header_injection(self):
        challenge = 'Digest realm="camera",nonce="test",algorithm=MD5,encrypt_type="3",qop="auth",opaque="test"'
        authorization = digest(challenge, sha("test-secret"), "client-nonce")
        self.assertIn('username="admin"', authorization)
        self.assertIn('uri="/stream"', authorization)
        self.assertNotIn("test-secret", authorization)
        self.assertNotIn(sha("test-secret"), authorization)
        for invalid in (challenge.replace('encrypt_type="3"', 'encrypt_type="1"'),
                        challenge.replace('realm="camera"', 'realm="camera\r\ninjected"'),
                        challenge.replace('qop="auth"', 'qop="auth-int"')):
            with self.assertRaises(ValueError):
                digest(invalid, sha("test-secret"), "client-nonce")

    def run_capture(self, part):
        wire = (b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"camera\","
                b"nonce=\"test\",algorithm=MD5,encrypt_type=\"3\",qop=\"auth\",opaque=\"test\"\r\n"
                b"Content-Length: 0\r\n\r\nHTTP/1.0 200 OK\r\n"
                b"Content-Type: multipart/mixed;boundary=--device-stream-boundary--\r\n\r\n" + part)
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.makefile.return_value = io.BytesIO(wire)
        with tempfile.TemporaryDirectory() as directory:
            with patch("camera_media.STORE", Path(directory)), \
                    patch("camera_media.os.path.ismount", return_value=True), \
                    patch("camera_media.os.statvfs", return_value=SimpleNamespace(f_bavail=200_000_000, f_frsize=1)), \
                    patch("camera_media.socket.create_connection", return_value=connection), \
                    patch("camera_media.time.monotonic", side_effect=[0, 0, 0, 0, 2, 2]):
                try:
                    result = capture("10.23.0.60", sha("test-secret"), seconds=1)
                except ValueError:
                    self.assertEqual(list(Path(directory).iterdir()), [])
                    raise
            result["data"] = Path(result["path"]).read_bytes()
            self.assertEqual(Path(result["path"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(connection.sendall.call_args_list), 3)
            preview = connection.sendall.call_args_list[-1].args[0].split(b"\r\n\r\n", 1)[1]
            self.assertTrue(preview.endswith(b"\r\n"))  # The camera waits for the multipart trailing separator.
            self.assertEqual(json.loads(preview)["params"]["method"], "get")
            return result

    def test_receives_bounded_synthetic_ts_and_never_changes_storage(self):
        packet = b"G" + b"\x00" * 187
        part = (b"----device-stream-boundary--\r\nContent-Type: video/mp2t\r\n"
                b"Content-Length: 188\r\nX-If-Encrypt: 0\r\n\r\n" + packet)
        result = self.run_capture(part)
        self.assertEqual(result["bytes"], 188)
        self.assertEqual(result["parts"], 1)
        self.assertEqual(result["data"], packet)

    def test_invalid_or_oversized_media_is_not_saved(self):
        for length, data in ((188, b"x" * 188), (2_000_001, b""), (188, b"short")):
            part = (b"----device-stream-boundary--\r\nContent-Type: video/mp2t\r\nContent-Length: "
                    + str(length).encode() + b"\r\n\r\n" + data)
            with self.assertRaises(ValueError):
                self.run_capture(part)

    def test_missing_mount_refuses_to_open_camera_or_create_file(self):
        with patch("camera_media.os.path.ismount", return_value=False), \
                patch("camera_media.socket.create_connection") as connect, \
                patch("camera_media.tempfile.mkstemp") as create:
            with self.assertRaisesRegex(ValueError, "mount"):
                capture("10.23.0.60", sha("test-secret"))
            connect.assert_not_called()
            create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
