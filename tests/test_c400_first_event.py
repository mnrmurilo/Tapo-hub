import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import check_c400_first_event as check


class FirstC400EventTests(unittest.TestCase):
    def test_registration_without_a_clip_never_passes_playback(self):
        self.run_check('no_event_observed')

    def test_failed_native_upload_is_reported_for_review(self):
        self.run_check('native_upload_needs_review', failure=True)

    def test_saved_clip_and_thumbnail_require_successful_camera_specific_playback(self):
        self.run_check('passed', video=True)
        self.run_check('playback_needs_review', video=True, returncode=1)

    def run_check(self, expected, *, video=False, failure=False, returncode=0):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            enrolled, result = root/'enrolled.json', root/'result.json'
            mac = '10:00:00:00:00:04'
            enrolled.write_text(json.dumps({mac: {'device_model': 'C400', 'hub_storage_enabled': True}}))
            if video:
                events = root/'events'
                events.mkdir()
                (events/'event-control.mp4.json').write_text(json.dumps({'camera_mac': mac,
                    'validated_recording': True, 'source_time': 100, 'event_type': 'MD'}))
                (events/'event-control.mp4').write_bytes(b'test video')
                (events/'event-control.jpg').write_bytes(b'test JPEG')
                (events/'event-control.jpg.json').write_text('{}')
            if failure:
                directory = root/'failed-uploads'/'c400'
                directory.mkdir(parents=True)
                (directory/'failed-control.wire.json').write_text('{}')
            with patch.object(check, 'STORE', root), patch.object(check, 'ENROLLED', enrolled), \
                    patch.object(check, 'RESULT', result), patch.object(check.time, 'monotonic', side_effect=[0, 0, 86401]), \
                    patch.object(check.time, 'sleep'), patch.object(check.subprocess, 'run', return_value=Mock(returncode=returncode)) as run, \
                    patch('builtins.print'):
                check.main()
            self.assertEqual(json.loads(result.read_text())['state'], expected)
            self.assertEqual(result.stat().st_mode & 0o777, 0o600)
            if video:
                self.assertEqual(run.call_args.args[0][-2:], ['--model', 'C400'])
            else:
                run.assert_not_called()
