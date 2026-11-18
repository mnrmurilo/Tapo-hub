import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import check_tc70_bind


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.mac = '10:00:00:00:00:02'
        (self.root / 'events').mkdir()
        (self.root / 'cameras.json').write_text(json.dumps({'devices': {self.mac: {'model': 'TC70'}}}))
        (self.root / 'state.json').write_text(json.dumps({'password_hash': 'A' * 64}))
        (self.root / 'continuous-status.json').write_text(json.dumps({'state': 'awaiting_pairing', 'checked_at': 1234}))
        self.media = self.root / 'events' / 'event-test.mp4'
        self.media.write_bytes(b'synthetic validated segment')
        Path(str(self.media) + '.json').write_text(json.dumps({'camera_mac': self.mac,
            'event_type': 'continuous', 'validated_recording': True, 'duration': 30,
            'source_time': 1200, 'bytes': self.media.stat().st_size}))
        self.camera = Mock()
        self.camera.read.return_value = {'error_code': 0}
        def batch(method, params):
            if method == 'setBindHubConfig':
                (self.root / 'enrolled.json').write_text(json.dumps({self.mac: {'hub_storage_enabled': True}}))
            return {'error_code': 0}
        self.camera._batch.side_effect = batch
        self.client = patch('check_tc70_bind.CameraProbe', return_value=self.camera).start()
        self.probe = patch('check_tc70_bind.probe', return_value={'address': '10.23.0.60',
            'device': {'device_model': 'TC70', 'hw_version': '5.0'}}).start()
        patch('check_tc70_bind.STATE', self.root).start()
        patch('check_tc70_bind.STORE', self.root).start()
        patch('check_tc70_bind.time.time', return_value=1234).start()
        # The network interface's MAC is the only non-state file read by this helper.
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            return '10:00:00:00:00:08' if str(path) == '/sys/class/net/eth0/address' else original_read(path, *args, **kwargs)
        patch.object(Path, 'read_text', read).start()
        self.addCleanup(patch.stopall)

    def test_no_binding_without_recent_validated_continuous_evidence(self):
        self.media.unlink()
        with self.assertRaisesRegex(ValueError, 'validated'):
            check_tc70_bind.main()
        self.client.assert_not_called()

    def test_wrong_hardware_or_unavailable_recorder_never_changes_destination(self):
        self.probe.return_value['device']['hw_version'] = '3.0'
        with self.assertRaises(ValueError):
            check_tc70_bind.main()
        self.client.assert_not_called()

    def test_binding_preserves_schedule_and_private_baseline(self):
        with patch('builtins.print'):
            check_tc70_bind.main()
        self.assertEqual([call.args[0] for call in self.camera._batch.call_args_list],
                         ['getRecordPlan', 'setBindHubConfig', 'getRecordPlan'])
        self.assertEqual((self.root / 'tc70-pre-bind.json').stat().st_mode & 0o777, 0o600)
        config = self.camera._batch.call_args_list[1].args[1]['hub_manage']['hub_config_set']['hub_storage']
        self.assertEqual(config['storage_enabled'], 'on')
        self.assertEqual(config['storage_mac'], '100000000008')


if __name__ == '__main__':
    unittest.main()
