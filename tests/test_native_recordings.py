import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_recordings import save_event


class NativeRecordingTests(unittest.TestCase):
    def test_recovered_partial_can_be_upgraded_but_cannot_replace_complete_video(self):
        self.metadata.update(endpoint='/stream/alarm_streaming', transfer_complete=False)
        decoded = {'video': b'\x00\x00\x01\x67sps\x00\x00\x01\x68pps', 'audio': b'',
                   'width': 2304, 'height': 1296, 'rate': 15, 'video_pts': [0, 1], 'source_time': 123,
                   'frame_types': {'video/x-h264': 2}}
        def media(arguments):
            if arguments[-1].endswith('.mp4'):
                Path(arguments[-1]).write_bytes(b'full' if self.metadata['transfer_complete'] else b'partial')
        with patch('native_recordings.decode_stream', side_effect=lambda *args: dict(decoded)), \
                patch('native_recordings.run_media', side_effect=media), \
                patch('native_recordings.subprocess.check_output', return_value=b'{"streams":[{"codec_type":"video"}]}'):
            result = save_event(self.body, self.metadata, 'B'*64, 'camera-a', recovered_partial=True)
            index = Path(result['path'] + '.json')
            partial = json.loads(index.read_text())
            self.assertTrue(partial['recovered_partial'])
            self.assertFalse(partial['native_upload']['transfer_complete'])
            self.metadata['transfer_complete'] = True
            with patch('native_recordings.run_media', side_effect=ValueError('failed validation')):
                with self.assertRaises(ValueError):
                    save_event(self.body, self.metadata, 'B'*64, 'camera-a')
            self.assertEqual(json.loads(index.read_text()), partial)
            result = save_event(self.body, self.metadata, 'B'*64, 'camera-a')
            self.assertFalse(result['duplicate'])
            self.assertFalse(json.loads(index.read_text())['recovered_partial'])
            self.assertEqual(Path(result['path']).read_bytes(), b'full')
            self.metadata['transfer_complete'] = False
            repeated = save_event(self.body, self.metadata, 'B'*64, 'camera-a', recovered_partial=True)
            self.assertTrue(repeated['duplicate'])
            self.assertEqual(Path(result['path']).read_bytes(), b'full')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Path(directory.name)
        self.body = self.store / "body.wire"
        self.body.write_bytes(b"encrypted")
        self.metadata = {"event_id": "123", "endpoint": "/stream/alarm_snapshot", "nonce": "a"*32,
                         "decrypt_length": "8", "captured_at": 1, "content_type": "image/jpeg"}
        for name, value in (("STORE", self.store), ("os.path.ismount", True),
                            ("disk_info", {"status": "normal"}),
                            ("os.statvfs", SimpleNamespace(f_bavail=500_000_000, f_frsize=1))):
            item = patch("native_recordings." + name, value) if name == "STORE" else patch("native_recordings." + name, return_value=value)
            item.start()
            self.addCleanup(item.stop)

    def test_snapshot_commit_is_private_idempotent_and_has_no_secrets(self):
        with patch("native_recordings.decode_snapshot", return_value=b"\xff\xd8test\xff\xd9"), \
                patch("native_recordings.run_media") as validate, \
                patch("native_recordings.subprocess.check_output", return_value=b'{"streams":[{"codec_type":"video"}]}'):
            result = save_event(self.body, self.metadata, "B"*64, "10:00:00:00:00:02")
            repeated = save_event(self.body, self.metadata, "B"*64, "10:00:00:00:00:02")
            self.assertTrue(repeated["duplicate"])
            validate.assert_called_once()
        image = Path(result["path"])
        self.assertEqual(image.stat().st_mode & 0o777, 0o600)
        index = Path(str(image) + ".json").read_text()
        self.assertNotIn("a"*32, index)
        self.assertNotIn("B"*64, index)
        self.assertFalse(json.loads(index)["validated_recording"])

    def test_codec_failure_does_not_publish_a_completed_event(self):
        with patch("native_recordings.decode_snapshot", return_value=b"jpeg"), \
                patch("native_recordings.run_media", side_effect=subprocess.CalledProcessError(1, "ffmpeg")):
            with self.assertRaises(subprocess.CalledProcessError):
                save_event(self.body, self.metadata, "B"*64, "10:00:00:00:00:02")
        self.assertEqual(list((self.store / "events").iterdir()), [])

    def test_missing_mount_never_writes_to_root_filesystem(self):
        with patch("native_recordings.os.path.ismount", return_value=False):
            with self.assertRaises(ValueError):
                save_event(self.body, self.metadata, "B"*64, "10:00:00:00:00:02")
        self.assertFalse((self.store / "events").exists())

    def test_mp4_without_expected_audio_is_not_published(self):
        self.metadata["endpoint"] = "/stream/alarm_streaming"
        decoded = {"video": b"h264", "audio": b"audio", "rate": 15, "audio_rate": 16000,
                   "frame_types": {"video/x-h264": 1, "audio/g711u": 1}}
        def media(arguments):
            if arguments[-1].endswith(".mp4"):
                Path(arguments[-1]).write_bytes(b"mp4")
        with patch("native_recordings.decode_stream", return_value=decoded), \
                patch("native_recordings.run_media", side_effect=media), \
                patch("native_recordings.subprocess.check_output", return_value=b'{"streams":[{"codec_type":"video"}]}'):
            with self.assertRaisesRegex(ValueError, "audio track"):
                save_event(self.body, self.metadata, "B"*64, "10:00:00:00:00:02")
        self.assertEqual(list((self.store / "events").iterdir()), [])

    def test_codec_reuse_requires_same_camera_and_video_profile(self):
        self.metadata["endpoint"] = "/stream/alarm_streaming"
        parameters = b"\x00\x00\x00\x01\x67sps\x00\x00\x00\x01\x68pps"
        picture = b"\x00\x00\x00\x01\x65picture"
        decoded = {"video": parameters + picture, "audio": b"", "rate": 15,
                   "width": 2304, "height": 1296, "frame_types": {"video/x-h264": 1}}
        inputs = []
        def media(arguments):
            if arguments[-1].endswith(".mp4"):
                inputs.append(Path(arguments[arguments.index("-i") + 1]).read_bytes())
                Path(arguments[-1]).write_bytes(b"mp4")
        with patch("native_recordings.decode_stream", side_effect=lambda *args: dict(decoded)), \
                patch("native_recordings.run_media", side_effect=media), \
                patch("native_recordings.subprocess.check_output", return_value=b'{"streams":[{"codec_type":"video"}]}'):
            save_event(self.body, self.metadata, "B"*64, "camera-a")
            decoded["video"] = picture
            for event_id, mac, width, expected in (("124", "camera-a", 2304, parameters + picture),
                                                    ("125", "camera-b", 2304, picture),
                                                    ("126", "camera-a", 640, picture)):
                self.metadata["event_id"] = event_id
                decoded["width"] = width
                save_event(self.body, self.metadata, "B"*64, mac)
                self.assertEqual(inputs[-1], expected)

    def test_failed_validation_does_not_cache_codec_parameters(self):
        self.metadata["endpoint"] = "/stream/alarm_streaming"
        decoded = {"video": b"\x00\x00\x01\x67sps\x00\x00\x01\x68pps", "audio": b"",
                   "width": 2304, "height": 1296, "rate": 15, "frame_types": {"video/x-h264": 1}}
        with patch("native_recordings.decode_stream", return_value=decoded), \
                patch("native_recordings.run_media", side_effect=subprocess.CalledProcessError(1, "ffmpeg")):
            with self.assertRaises(subprocess.CalledProcessError):
                save_event(self.body, self.metadata, "B"*64, "camera-a")
        self.assertFalse((self.store / "events" / ".codecs").exists())
