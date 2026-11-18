from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from continuous_audio import AudioPES
from continuous_recording import publish, record_session


def packet(pid, payload, counter=0, first=True):
    adaptation = 183 - len(payload)
    assert 0 <= adaptation <= 183
    return (bytes([0x47, (pid >> 8) | (64 if first else 0), pid & 255, 0x30 | counter,
                   adaptation]) + (bytes(adaptation) if adaptation else b'') + payload)


def tables():
    pat = bytes.fromhex('0000b00d2e66cf00000001e0125705669f')
    pmt = bytes.fromhex('0002b0170001f10000e044f0001be044f00091e045800018adc0be')
    return packet(0, pat) + packet(18, pmt)


class AudioTests(unittest.TestCase):
    def test_private_track_extracts_complete_mulaw_and_ignores_video(self):
        parser = AudioPES()
        self.assertEqual(parser.feed(tables()), [])
        self.assertEqual(parser.pid, 69)
        audio = bytes(range(256))
        pes = b'\x00\x00\x01\xc0' + (len(audio) + 8).to_bytes(2, 'big') + b'\x80\x80\x05' + bytes(5) + audio
        self.assertEqual(parser.feed(packet(68, b'video') + packet(69, pes[:180])), [])
        self.assertEqual(parser.feed(packet(69, pes[180:], counter=1, first=False)), [audio])

    def test_packet_loss_and_truncation_fail_instead_of_silent_audio_corruption(self):
        parser = AudioPES()
        parser.feed(tables())
        pes = b'\x00\x00\x01\xc0\x01\x08\x80\x80\x05' + bytes(5) + bytes(256)
        parser.feed(packet(69, pes[:180]))
        with self.assertRaisesRegex(ValueError, 'loss'):
            parser.feed(packet(69, pes[180:], counter=2, first=False))
        for invalid in (b'G', b'\x00' * 188):
            with self.assertRaises(ValueError):
                AudioPES().feed(invalid)

    def test_unsupported_table_layout_is_rejected(self):
        with self.assertRaises(ValueError):
            AudioPES().feed(packet(0, bytes.fromhex('0000bfff')))


class PublisherTests(unittest.TestCase):
    def test_low_space_never_opens_camera(self):
        with patch('continuous_recording.check_store'), patch('continuous_recording.free_bytes', return_value=0), \
                patch('continuous_recording.preview_packets') as connect:
            with self.assertRaises(ValueError):
                record_session('10.23.0.60', 'unused', '02:00:00:00:01:02')
            connect.assert_not_called()

    @unittest.skipUnless(shutil.which('ffmpeg'), 'FFmpeg required for recording publication')
    def test_published_audio_video_thumbnail_and_retention_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Path(temporary)
            source = store / 'part.mp4'
            subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'color=s=64x64:r=10',
                            '-f', 'lavfi', '-i', 'anullsrc=r=16000:cl=mono', '-t', '1',
                            '-c:v', 'libx264', '-c:a', 'aac', str(source)], check=True, timeout=15)
            mac, start = '02:00:00:00:01:02', 1794400000
            with patch('continuous_recording.STORE', store), patch('continuous_recording.activity', nullcontext):
                result = publish(source, mac, start)
            stem = 'event-' + hashlib.sha256((mac + ':' + str(start * 1000000)).encode()).hexdigest()[:24]
            index = store / 'events' / (stem + '.mp4.json')
            metadata = json.loads(index.read_text())
            self.assertEqual(metadata['event_type'], 'continuous')
            self.assertEqual(metadata['source_time'], start)
            self.assertAlmostEqual(result['duration'], 1, delta=.15)
            self.assertEqual(index.stat().st_mode & 0o777, 0o600)
            with patch('recording_retention.STORE', store):
                from recording_retention import completed_group
                self.assertEqual(len(completed_group(stem)[0]), 4)
            self.assertFalse(source.exists())


if __name__ == '__main__':
    unittest.main()
