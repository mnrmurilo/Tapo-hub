from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import check_td21_next_event as check
from check_tapo_playback import select_recording


class TD21VerificationTests(unittest.TestCase):
    def test_recovered_fragment_is_not_proof_of_complete_native_upload(self):
        key = self.video()
        index = self.root/'events'/(key+'.mp4.json')
        metadata = json.loads(index.read_text())
        metadata['recovered_partial'] = True
        index.write_text(json.dumps(metadata))
        self.assertEqual(check.inspect_recordings(self.mac, 150), [])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.result = self.root/'result.json'
        self.mac = '10:00:00:00:00:02'
        (self.root/'events').mkdir()
        (self.root/'enrolled.json').write_text(json.dumps({self.mac: {
            'device_model': 'TD21', 'hub_storage_enabled': True}}))
        self.clock = 0
        for target, value in (('ROOT', self.root), ('STORE', self.root), ('RESULT', self.result)):
            patch.object(check, target, value).start()
        patch.object(check, 'activity', nullcontext).start()
        patch.object(check.time, 'time', return_value=200).start()
        patch.object(check.time, 'monotonic', side_effect=lambda: self.clock).start()
        self.sleep = patch.object(check.time, 'sleep', side_effect=self.advance).start()
        self.playback = patch.object(check.subprocess, 'run', return_value=Mock(returncode=0)).start()
        self.faces = patch.object(check, 'face_status', return_value={
            'state': 'complete', 'analyzed': True, 'face_count': 0, 'familiar_count': 0, 'stranger_count': 0}).start()
        self.addCleanup(patch.stopall)

    def advance(self, seconds):
        self.clock += seconds

    def video(self, stamp=200, key=None, mac=None):
        key = key or 'event-'+'b'*24
        media = self.root/'events'/(key+'.mp4')
        media.write_bytes(b'synthetic verified test video')
        media.with_suffix('.mp4.json').write_text(json.dumps({'camera_mac': mac or self.mac,
            'source_time': stamp, 'validated_recording': True, 'format_version': 1,
            'bytes': media.stat().st_size, 'event_type': 'MD'}))
        media.with_suffix('.jpg').write_bytes(b'synthetic test JPEG')
        media.with_suffix('.jpg.json').write_text('{}')
        return key

    def report(self):
        return json.loads(self.result.read_text())

    def test_old_or_other_camera_footage_cannot_pass_a_new_td21_check(self):
        self.video(stamp=100)
        self.video(mac='10:00:00:00:00:04', key='event-'+'a'*24)
        check.run(150, seconds=6)
        self.assertEqual(self.report()['state'], 'observation_ended_without_verification')
        self.playback.assert_not_called()
        self.faces.assert_not_called()

    def test_exact_new_clip_and_completed_analysis_can_pass_with_zero_detected_faces(self):
        key = self.video()
        self.faces.side_effect = [{'state': 'pending', 'analyzed': False}, self.faces.return_value]
        check.run(150, seconds=16)
        self.assertEqual(self.playback.call_count, 1)
        self.assertEqual(self.playback.call_args.args[0][-4:], ['--model', 'TD21', '--file-id', key])
        result = self.report()
        self.assertEqual(result['state'], 'passed')
        self.assertEqual(result['face_count'], 0)
        self.assertTrue(result['face_analysis_complete'])
        self.assertEqual(self.result.stat().st_mode & 0o777, 0o600)

    def test_playback_failure_is_not_a_face_analysis_success(self):
        self.video()
        self.playback.return_value.returncode = 1
        check.run(150, seconds=16)
        self.assertEqual(self.report()['state'], 'playback_needs_review')
        self.faces.assert_not_called()

    def test_disabled_analysis_is_reported_without_enabling_it(self):
        self.video()
        self.faces.return_value = {'state': 'disabled', 'analyzed': False}
        check.run(150, seconds=16)
        self.assertEqual(self.report()['state'], 'face_analysis_disabled')

    def test_an_interrupted_upload_can_be_followed_by_a_successful_retry(self):
        directory = self.root/'failed-uploads'/'td21'
        directory.mkdir(parents=True)
        (directory/'failed-test.wire.json').write_text(json.dumps({'camera_mac': self.mac, 'captured_at': 200}))
        self.assertEqual(check.recent_failures(self.mac, 150), 1)
        def later(seconds):
            self.advance(seconds)
            self.video()
        self.sleep.side_effect = later
        check.run(150, seconds=16)
        self.assertEqual(self.report()['state'], 'passed')

    def test_playback_selection_targets_exact_camera_and_rejects_paths(self):
        old = self.video(stamp=100, key='event-'+'a'*24)
        new = self.video()
        self.assertEqual(select_recording(self.root/'events', self.mac).name, old+'.mp4.json')
        self.assertEqual(select_recording(self.root/'events', self.mac, new).name, new+'.mp4.json')
        for key in ('../../private', 'event-'+'c'*24):
            with self.assertRaises(ValueError):
                select_recording(self.root/'events', self.mac, key)
        with self.assertRaises(ValueError):
            select_recording(self.root/'events', '10:00:00:00:00:04', new)


if __name__ == '__main__':
    unittest.main()
