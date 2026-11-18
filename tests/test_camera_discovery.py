import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import threading
from types import SimpleNamespace

from camera_discovery import respond, command, LocalScan
from camera_registry import CameraRegistry
from hub_lab import packet, decode_probe


class DiscoveryTests(unittest.TestCase):
    def test_tc70_requires_verified_v5_hardware(self):
        from camera_registry import camera_supported
        for hardware, supported in (('', False), ('3.0', False), ('5.0', True)):
            self.assertEqual(camera_supported({'model': 'TC70', 'hardware_version': hardware}), supported)

    def test_configured_c400_v2_scan_is_observed_but_other_hardware_is_deferred(self):
        mac = '10:00:00:00:00:04'
        setup = SimpleNamespace(state={'owner': 'A'*32})
        device = {'mac': '10-00-00-00-00-08', 'dev_id': 'B'*40, 'device_model': 'H500'}
        params = {'device_model': 'C400', 'mac': mac, 'ip': '10.23.0.78', 'owner': 'A'*32, 'auth_type': 'SHA256'}
        for hardware in ('1.0', '2.0'):
            registry = SimpleNamespace(lock=threading.Lock(), devices={mac: {'model': 'C400', 'hardware_version': hardware}}, observe=MagicMock())
            raw = packet({'params': params}, b'TEST', opcode=4, flags=0x21, reserved=1)
            result = respond(raw, '10.23.0.78', '10.23.0.72', device, setup, registry, packet, decode_probe)
            self.assertEqual(result is not None, hardware == '2.0')
            self.assertEqual(registry.observe.called, hardware == '2.0')

    def test_tc70_and_unverified_c400_hardware_remain_deferred(self):
        mac = "10:00:00:00:00:02"
        setup = SimpleNamespace(state={"owner": "A"*32})
        for model in ("TC70", "C400"):
            registry = SimpleNamespace(lock=threading.Lock(), devices={mac: {"model": model}}, observe=MagicMock())
            raw = packet({"params": {"device_model": model, "mac": mac, "ip": "10.23.0.52",
                                     "owner": "A"*32, "auth_type": "SHA256"}}, opcode=4, flags=0x21, reserved=1)
            self.assertIsNone(respond(raw, "10.23.0.52", "10.23.0.72", {}, setup, registry, packet, decode_probe))
            registry.observe.assert_not_called()

    def test_app_scan_verifies_td21_identity_before_requesting_discovery(self):
        mac = "10:00:00:00:00:02"
        registry = SimpleNamespace(lock=threading.Lock(), devices={mac: {"model": "TD21"}},
                                   resolve=lambda _: "10.23.0.52")
        setup = SimpleNamespace(auth=SimpleNamespace(password_hash="A"*64))
        for returned_mac in (mac, "10:00:00:00:00:04"):
            scan = LocalScan(registry, "10.23.0.72", setup)
            with patch("camera_discovery.socket.create_connection", return_value=MagicMock()), \
                    patch("camera_discovery.CameraProbe") as client, \
                    patch.object(scan.stop, "wait"):
                camera = client.return_value
                camera.read.return_value = {"error_code": 0, "result": {"device_info": {
                    "basic_info": {"mac": returned_mac, "device_model": "TD21"}}}}
                camera.scan_hubs.return_value = {"error_code": 0}
                scan.begin()
                scan.thread.join(timeout=1)
                self.assertFalse(scan.running)
                if returned_mac == mac:
                    camera.scan_hubs.assert_called_once_with("10.23.0.72")
                else:
                    camera.scan_hubs.assert_not_called()

    def test_configured_camera_scan_response_matches_transaction_and_preserves_unpaired_state(self):
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory)/"seed.json"
            seed.write_text(json.dumps({"devices": {"10:00:00:00:00:02": {
                "model": "TD21", "seed_ip": "10.23.0.52", "last_ip": None, "last_seen": 0}}, "pending": []}))
            registry = CameraRegistry(Path(directory)/"registry.json", seed)
            setup = SimpleNamespace(state={"owner": "A"*32, "device_alias": "Test Hub"})
            device = {"mac": "10-00-00-00-00-04", "dev_id": "B"*40, "device_model": "H500"}
            params = {"device_model": "TD21", "mac": "100000000002", "ip": "10.23.0.52",
                      "owner": "A"*32, "auth_type": "SHA256"}
            def reply(fields=params, peer="10.23.0.52", opcode=4):
                raw = packet({"params": fields}, b"TEST", opcode=opcode, flags=0x21, reserved=1)
                return respond(raw, peer, "10.23.0.72", device, setup, registry, packet, decode_probe)
            raw = reply()
            self.assertEqual(raw[8:12], b"TEST")
            self.assertEqual(raw[6:8], b"\x22\x01")
            result = decode_probe(raw, expected_opcode=4)["result"]
            self.assertEqual(result["device_id"], device["dev_id"])
            self.assertEqual(result["max_bound"], 3)
            self.assertEqual(result["current_bound"], 0)
            self.assertEqual(result["storage_media_status"], 0)
            self.assertEqual(registry.resolve(params["mac"]), "10.23.0.52")
            listing = command("getScanGeneralDeviceList", {"general_camera_manage": {
                "general_device_list": {}}}, registry)
            self.assertEqual(len(listing["result"]["general_camera_manage"]["general_device_list"]), 1)
            self.assertEqual(listing["result"]["general_camera_manage"]["general_device_list"][0]["device_model"], "TD21")
            self.assertEqual(listing["result"]["general_camera_manage"]["general_device_list"][0]["bind_check"], 1004)
            paired = command("getGeneralDeviceList", {"general_camera_manage": {
                "paired_general_device_list": {}}}, registry)
            # Real hub clients require the module envelope; flat counters parse as absent on some clients.
            self.assertEqual(set(paired["result"]), {"general_camera_manage"})
            self.assertEqual(paired["result"]["general_camera_manage"]["max_bound"], 3)
            self.assertEqual(paired["result"]["general_camera_manage"]["current_bound"], 0)
            self.assertEqual(paired["result"]["general_camera_manage"]["paired_general_device_list"], [])
            observed_time = registry.devices["10:00:00:00:00:02"]["hub_discovery"]["last_seen"]
            stale = command("getScanGeneralDeviceList", {"general_camera_manage": {
                "general_device_list": {}}}, registry, now=observed_time + 601)
            self.assertEqual(stale["result"]["general_camera_manage"]["general_device_list"], [])
            self.assertNotEqual(command("getGeneralDeviceList", {}, registry)["error_code"], 0)
            for key, value in (("owner", "C"*32), ("mac", "100000000006"),
                               ("device_model", "C400"), ("ip", "10.23.0.78")):
                self.assertIsNone(reply({**params, key: value}))
            self.assertIsNone(reply(peer="1.1.1.1"))
            with self.assertRaises(ValueError):
                reply(opcode=1)
            with self.assertRaises(ValueError):
                decode_probe(raw)  # Generic app discovery still only accepts opcode 1.
            corrupt = bytearray(raw)
            corrupt[-1] ^= 1
            with self.assertRaises(ValueError):
                decode_probe(corrupt, expected_opcode=4)


if __name__ == "__main__":
    unittest.main()
