import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from manage import prepare_store, validate_cameras
from settings import validate


class SetupTests(unittest.TestCase):
    def test_camera_allowlist_is_mac_keyed_and_rejects_unknown_or_conflicting_inputs(self):
        camera = {'model': 'C400', 'hardware_version': '2.0', 'mac': '02-00-00-00-00-01', 'ip': '10.23.0.10'}
        network = ipaddress.IPv4Network('10.23.0.0/24')
        result = validate_cameras([camera], network)
        self.assertEqual(result['devices']['02:00:00:00:00:01']['seed_ip'], '10.23.0.10')
        self.assertEqual(validate_cameras([], network), {'devices': {}, 'pending': []})
        for cameras in ([camera, camera], [{**camera, 'hardware_version': '1.0'}],
                        [{**camera, 'ip': '10.24.0.10'}], [{**camera, 'continuous': True}]):
            with self.assertRaises(ValueError):
                validate_cameras(cameras, network)

    def test_network_and_storage_configuration_refuses_public_or_mismatched_addresses(self):
        config = {'lan_cidr': '10.23.0.0/24', 'hub_ip': '10.23.0.2',
                  'recording_path': '/var/lib/tapo-hub/recordings'}
        self.assertEqual(validate(config), config)
        for extra in ({'hub_ip': '10.24.0.2'}, {'lan_cidr': '8.8.8.0/24', 'hub_ip': '8.8.8.8'},
                      {'recording_path': '/other-app/photos'}, {'hub_ip': '10.23.0.255'}):
            with self.assertRaises(ValueError):
                validate({**config, **extra})

    def test_storage_refuses_root_and_existing_unrelated_data(self):
        with tempfile.TemporaryDirectory() as work:
            store = Path(work)
            (store/'important.txt').write_text('preserve')
            with patch('manage.os.path.ismount', return_value=True):
                with self.assertRaises(ValueError):
                    prepare_store(store)  # Same filesystem as root is always refused.
            original_stat = Path.stat
            def stat(path, *args, **kwargs):
                return SimpleNamespace(st_dev=-1) if str(path) == '/' else original_stat(path, *args, **kwargs)
            with patch('manage.os.path.ismount', return_value=True), patch('pathlib.Path.stat', stat):
                with self.assertRaisesRegex(ValueError, 'contains other data'):
                    prepare_store(store)
                self.assertEqual((store/'important.txt').read_text(), 'preserve')
                (store/'important.txt').unlink()
                prepare_store(store)
                self.assertEqual(json.loads((store/'.tapo-hub-store').read_text())['application'], 'tapo-hub')
                prepare_store(store)  # Reconfiguration is safe for an initialized store.
