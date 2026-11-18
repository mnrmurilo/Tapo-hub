import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from camera_registry import CameraRegistry, normalize_mac, scan_once


class RegistryTests(unittest.TestCase):
    def test_removing_discovery_candidates_does_not_keep_scanning_saved_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, seed = self.make_registry(directory)
            self.assertTrue(registry.observe({'mac': '02:00:00:00:00:04', 'device_model': 'C400',
                                              'hardware_version': '2.0'}, '10.23.0.78'))
            restored = CameraRegistry(Path(directory)/'cameras.json', seed)
            self.assertIn('02:00:00:00:00:04', restored.devices)
            seed.write_text(json.dumps({'devices': {}, 'pending': []}))
            restored = CameraRegistry(Path(directory)/'cameras.json', seed)
            self.assertEqual(restored.devices, {})
            self.assertEqual(restored.pending, [])
    def test_background_scan_includes_only_known_c400_v2_and_td21(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, _ = self.make_registry(directory)
            registry.devices['10:00:00:00:00:02'] = {'model': 'TD21', 'seed_ip': '10.23.0.52'}
            registry.devices['10:00:00:00:00:04'] = {'model': 'C400', 'hardware_version': '2.0', 'seed_ip': '10.23.0.78'}
            with patch('camera_registry.socket.socket') as factory, patch('camera_registry.time.monotonic', side_effect=[0, 4]):
                scan_once(registry, lambda *args: b'probe', lambda *args: {})
                stream = factory.return_value.__enter__.return_value
                self.assertEqual({call.args[1] for call in stream.sendto.call_args_list},
                                 {('10.23.0.52', 20002), ('10.23.0.78', 20002)})

    def test_background_scan_only_contacts_td21_without_broadcast(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, _ = self.make_registry(directory)
            registry.devices["10:00:00:00:00:02"] = {"model": "TD21", "seed_ip": "10.23.0.52",
                                                        "last_ip": "10.23.0.53"}
            with patch("camera_registry.socket.socket") as factory, \
                    patch("camera_registry.time.monotonic", side_effect=[0, 4]):
                stream = factory.return_value.__enter__.return_value
                scan_once(registry, lambda *args: b"probe", lambda *args: {})
                self.assertEqual({call.args[1] for call in stream.sendto.call_args_list},
                                 {("10.23.0.52", 20002), ("10.23.0.53", 20002)})
                stream.setsockopt.assert_not_called()

    def make_registry(self, directory):
        seed = Path(directory)/"seed.json"
        seed.write_text(json.dumps({"devices": {
            "02:00:00:00:01:02": {"model": "TC70", "seed_ip": "10.23.0.60", "last_ip": None, "last_seen": 0}},
            "pending": [{"model": "C400", "seed_ip": "10.23.0.78"}]}))
        return CameraRegistry(Path(directory)/"cameras.json", seed), seed

    def test_mac_identity_survives_ip_change_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, seed = self.make_registry(directory)
            reply = {"mac": "02-00-00-00-01-02", "device_model": "TC70(EU)"}
            self.assertTrue(registry.observe(reply, "10.23.0.60", now=1000))
            self.assertTrue(registry.observe(reply, "10.23.1.10", now=1010))
            self.assertEqual(len(registry.devices), 1)
            self.assertEqual(registry.resolve("02:00:00:00:01:02", now=1011), "10.23.1.10")
            restored = CameraRegistry(registry.path, seed)
            self.assertEqual(restored.resolve(reply["mac"], now=1011), "10.23.1.10")
            self.assertIsNone(restored.resolve(reply["mac"], now=1200))
            self.assertEqual(registry.path.stat().st_mode & 0o777, 0o600)

    def test_unknown_or_mismatched_devices_do_not_replace_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, _ = self.make_registry(directory)
            self.assertFalse(registry.observe({"mac": "10:22:33:44:55:66", "device_model": "TC70"}, "10.23.0.60"))
            self.assertFalse(registry.observe({"mac": "02:00:00:00:01:02", "device_model": "C400"}, "10.23.0.60"))
            self.assertFalse(registry.observe({"mac": "02:00:00:00:01:02", "device_model": "TC70"}, "19.168.68.52"))
            self.assertEqual(len(registry.devices), 1)

    def test_pending_device_requires_both_seed_address_and_model(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, _ = self.make_registry(directory)
            reply = {"mac": "10:22:33:44:55:66", "device_model": "C400"}
            self.assertFalse(registry.observe(reply, "10.23.0.79"))
            self.assertFalse(registry.observe({**reply, "device_model": "C401"}, "10.23.0.78"))
            self.assertTrue(registry.observe(reply, "10.23.0.78"))
            self.assertEqual(registry.pending, [])
            self.assertIn(reply["mac"], registry.devices)

    def test_address_reuse_clears_previous_camera_address(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, _ = self.make_registry(directory)
            registry.observe({"mac": "02:00:00:00:01:02", "device_model": "TC70"}, "10.23.0.78", now=1000)
            registry.observe({"mac": "10:22:33:44:55:66", "device_model": "C400"}, "10.23.0.78", now=1001)
            self.assertIsNone(registry.resolve("02:00:00:00:01:02", now=1002))

    def test_invalid_mac_addresses(self):
        for value in (None, "", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "bad"):
            with self.assertRaises(ValueError):
                normalize_mac(value)

    def test_new_confirmed_mac_preserves_existing_address(self):
        with tempfile.TemporaryDirectory() as directory:
            registry, seed = self.make_registry(directory)
            registry.observe({"mac": "02:00:00:00:01:02", "device_model": "TC70"}, "10.23.1.10", now=1000)
            config = json.loads(seed.read_text())
            config["devices"]["02:00:00:00:01:03"] = {"model": "C400", "seed_ip": "10.23.0.78"}
            config["pending"] = []
            seed.write_text(json.dumps(config))
            restored = CameraRegistry(registry.path, seed)
            self.assertEqual(restored.resolve("02:00:00:00:01:02", now=1001), "10.23.1.10")
            self.assertEqual(restored.pending, [])
            self.assertEqual(restored.devices["02:00:00:00:01:03"]["model"], "C400")

    def test_arp_pins_pending_mac_and_follows_address_change(self):
        header = "IP address HW type Flags HW address Mask Device\n"
        with tempfile.TemporaryDirectory() as directory:
            registry, _ = self.make_registry(directory)
            registry.refresh_neighbors(header + "10.23.0.78 0x1 0x2 02:00:00:00:01:03 * eth0\n", now=1000)
            self.assertEqual(registry.pending, [])
            self.assertEqual(registry.resolve("02:00:00:00:01:03", now=1001), "10.23.0.78")
            registry.refresh_neighbors(header + "10.23.0.79 0x1 0x2 02:00:00:00:01:03 * eth0\n", now=1010)
            self.assertEqual(registry.resolve("02:00:00:00:01:03", now=1011), "10.23.0.79")
            self.assertEqual(registry.devices["02:00:00:00:01:03"]["model"], "C400")

    def test_incomplete_or_ambiguous_arp_does_not_choose_an_address(self):
        header = "IP address HW type Flags HW address Mask Device\n"
        with tempfile.TemporaryDirectory() as directory:
            registry, _ = self.make_registry(directory)
            registry.refresh_neighbors(header + "10.23.0.78 0x1 0x0 00:00:00:00:00:00 * eth0\n", now=1000)
            self.assertEqual(len(registry.pending), 1)
            registry.refresh_neighbors(header + "10.23.0.60 0x1 0x2 02:00:00:00:01:02 * eth0\n"
                                       + "10.23.0.61 0x1 0x2 02:00:00:00:01:02 * eth0\n", now=1000)
            self.assertIsNone(registry.resolve("02:00:00:00:01:02", now=1001))


if __name__ == "__main__":
    unittest.main()
