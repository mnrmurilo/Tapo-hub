import copy
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_storage import NativeStorage
from hub_lab import Diagnostics


class NativeStorageTests(unittest.TestCase):
    def test_c400_v2_enrollment_and_dhcp_sync_preserve_td21(self):
        self.register()
        td21 = dict(self.storage.devices[self.mac])
        mac, peer = '10:00:00:00:00:04', '10.23.0.78'
        self.cameras.devices[mac] = {'model': 'C400', 'hardware_version': '2.0', 'last_ip': peer}
        params = copy.deepcopy(self.params)
        info = params['general_camera_manage']['storage_info']
        info['mac'] = mac
        info['basic_info'].update(model='C400', device_id='D'*40, ipaddr=peer)
        with patch('native_storage.os.path.ismount', return_value=True), \
                patch('native_storage.os.statvfs', return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)):
            self.assertEqual(self.storage.command(params, peer)['error_code'], 0)
        restarted = NativeStorage(self.path, self.cameras, self.setup, self.device)
        self.assertEqual(restarted.devices[self.mac], td21)
        self.assertEqual(restarted.public_list()['current_bound'], 2)
        moved = '10.23.0.79'
        self.cameras.devices[mac]['last_ip'] = moved
        request = {'general_camera_manage': {'config_sync': {'mac': mac,
            'basic_info': {'device_id': 'D'*40, 'model': 'C400'}, 'ip': moved,
            'storage_mac': self.device['mac'], 'hub_storage_enabled': 1}}}
        self.assertEqual(restarted.sync(request, moved)['error_code'], 0)
        self.assertEqual(restarted.devices[mac]['ip_addr'], moved)
        self.assertEqual(restarted.devices[self.mac], td21)

    def setUp(self):
        disk = patch("native_storage.disk_info", return_value={"status": "normal"})
        disk.start()
        self.addCleanup(disk.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.mac = "10:00:00:00:00:02"
        self.path = Path(self.directory.name)/"enrolled.json"
        self.cameras = SimpleNamespace(lock=threading.Lock(), devices={self.mac: {
            "model": "TD21", "last_ip": "10.23.0.52"}})
        self.setup = SimpleNamespace(auth=SimpleNamespace(password_hash="A"*64), state={})
        self.device = {"dev_id": "B"*40, "mac": "10:00:00:00:00:08", "ipaddr": "10.23.0.72",
                       "device_model": "H500", "device_type": "SMART.TAPOHUB"}
        self.storage = NativeStorage(self.path, self.cameras, self.setup, self.device)
        self.params = {"general_camera_manage": {"storage_info": {
            "mac": self.mac.replace(":", ""), "enabled": "on",
            "bind_code": "12345678-1234-1234-1234-123456789abc", "resolution": "2304*1296",
            "storage_schedule_status": 0, "basic_info": {"device_id": "C"*40,
                "type": "SMART.IPCAMERA", "model": "TD21", "ipaddr": "10.23.0.52",
                "alias": "Test TD21", "network_mode": "wireless"}}}}

    def register(self):
        with patch("native_storage.os.path.ismount", return_value=True), \
                patch("native_storage.os.statvfs", return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch("native_storage.threading.Thread") as job:
            first = self.storage.command(self.params, "10.23.0.52")
            second = self.storage.command(self.params, "10.23.0.52")
            self.assertEqual(first["error_code"], 0)
            self.assertEqual(second["error_code"], 0)
            job.assert_not_called()

    def test_explicit_authenticated_registration_persists_and_keeps_secrets_out_of_app_list(self):
        self.register()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        restarted = NativeStorage(self.path, self.cameras, self.setup, self.device)
        listing = restarted.public_list()
        self.assertEqual(restarted.devices[self.mac]["recording_mode"], "persistent_native")
        self.assertEqual(restarted.devices[self.mac]["restore_status"], "not_scheduled")
        self.assertFalse(hasattr(restarted, "recover_pending_restores"))
        self.assertEqual(listing["current_bound"], 1)
        self.assertEqual(listing["paired_general_device_list"][0]["device_id"], "C"*40)
        self.assertNotIn("bind_code", json.dumps(listing))
        self.assertNotIn("password", json.dumps(listing))

    def test_registration_batch_contains_the_storage_status_required_by_camera(self):
        handler = object.__new__(Diagnostics)
        handler.client_address = ("10.23.0.52", 12345)
        handler.server = SimpleNamespace(native_storage=self.storage)
        with patch("native_storage.os.path.ismount", return_value=True), \
                patch("native_storage.os.statvfs", return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch("native_storage.threading.Thread"):
            reply = handler.dispatch({"method": "multipleRequest", "params": {"requests": [
                {"method": "storageHubRequest", "params": self.params}]}})
        response = reply["result"]["responses"][0]
        self.assertEqual(response, {"method": "storageHubRequest", "error_code": 0,
            "result": {"general_camera_manage": {"storage_info": {
                "storage_media_status": 1, "hub_cam_capability": 0, "basic_info": {
                    "device_id": "B"*40, "ipaddr": "10.23.0.72", "model": "H500",
                    "type": "SMART.TAPOHUB", "auth_type": "NONE", "alias": "Tapo Hub",
                    "mac": "100000000008", "hub_id": "B"*8, "ai_hub_support": 0}}}}})
        self.assertNotIn("bind_code", json.dumps(reply))
        self.assertNotIn("A"*64, json.dumps(reply))

    def test_wrong_peer_camera_model_and_identity_never_create_registration(self):
        for peer, key, value in (("10.23.0.74", "model", "TD21"),
                                 ("10.23.0.52", "model", "C400"),
                                 ("10.23.0.52", "device_id", "bad-id"),
                                 ("10.23.0.52", "ipaddr", "10.23.0.78")):
            params = copy.deepcopy(self.params)
            params["general_camera_manage"]["storage_info"]["basic_info"][key] = value
            with patch("native_storage.threading.Thread") as job:
                self.assertNotEqual(self.storage.command(params, peer)["error_code"], 0)
                job.assert_not_called()
                self.assertFalse(self.path.exists())

    def test_missing_recording_mount_rejects_activation(self):
        with patch("native_storage.os.path.ismount", return_value=False):
            self.assertNotEqual(self.storage.command(self.params, "10.23.0.52")["error_code"], 0)
        self.assertFalse(self.path.exists())

    def test_unhealthy_disk_does_not_advertise_native_storage_ready(self):
        self.register()
        with patch("native_storage.os.path.ismount", return_value=True), \
                patch("native_storage.os.statvfs", return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                patch("native_storage.disk_info", return_value={"status": "abnormal"}):
            self.assertEqual(self.storage.command(self.params, "10.23.0.52")["error_code"], -40101)
        self.assertTrue(self.storage.devices[self.mac]["hub_storage_enabled"])

    def test_native_binding_token_is_opaque_and_preserved_exactly(self):
        token = "native_binding_token_not_a_uuid_123456"
        self.params["general_camera_manage"]["storage_info"]["bind_code"] = token
        self.register()
        self.assertEqual(self.storage.devices[self.mac]["bind_code"], token)
        self.assertNotIn(token, json.dumps(self.storage.public_list()))

    def test_http_dispatch_reports_only_real_native_registration(self):
        handler = object.__new__(Diagnostics)
        handler.client_address = ("10.23.0.52", 12345)
        handler.server = SimpleNamespace(native_storage=self.storage, cameras=self.cameras)
        request = {"method": "getGeneralDeviceList", "params": {
            "general_camera_manage": {"paired_general_device_list": {}}}}
        self.assertEqual(handler.dispatch(request)["result"]["general_camera_manage"]["current_bound"], 0)
        self.register()
        self.assertEqual(handler.dispatch(request)["result"]["general_camera_manage"]["current_bound"], 1)

    def test_native_sync_preserves_association_and_returns_firmware_parser_fields(self):
        self.register()
        params = {"general_camera_manage": {"config_sync": {
            "mac": self.mac, "basic_info": {"device_id": "C"*40, "model": "TD21"},
            "ip": "10.23.0.52", "storage_mac": self.device["mac"], "hub_storage_enabled": 1}}}
        handler = object.__new__(Diagnostics)
        handler.client_address = ("10.23.0.52", 12345)
        handler.server = SimpleNamespace(native_storage=self.storage)
        with patch("native_storage.disk_info", return_value={"status": "normal"}):
            response = handler.dispatch({"method": "syncHubRequest", "params": params})
            self.assertEqual(response["error_code"], 0)
            config = response["result"]["general_camera_manage"]["config_sync"]
            self.assertEqual(config, {"zone_id": "Etc/UTC", "timezone": "UTC+00:00",
                "storage_media_status": 1, "hub_cam_capability": 0, "chn_num": 0,
                "ai_enhance_enabled": 0, "ALGbitmap": 0, "ai_hub_support": 0})
            self.assertTrue(self.storage.devices[self.mac]["camera_storage_enabled"])
            self.assertTrue(self.storage.devices[self.mac]["hub_storage_enabled"])
            self.assertEqual(self.storage.devices[self.mac]["restore_status"], "not_scheduled")
            self.assertEqual(self.storage.sync(params, "10.23.0.60")["error_code"], -40401)
            params["general_camera_manage"]["config_sync"]["basic_info"]["device_id"] = "D"*40
            self.assertEqual(self.storage.sync(params, "10.23.0.52")["error_code"], -40401)

    def test_associated_td21_does_not_trip_app_recording_destination_capacity_check(self):
        self.register()
        listing = self.storage.public_list()
        # Tapo's destination screen rejects suggested hubs when current_bound >= max_bound.
        self.assertLess(listing["current_bound"], listing["max_bound"])
        self.assertEqual(len(listing["paired_general_device_list"]), 1)

    def test_admission_limit_still_rejects_additional_cameras_when_full(self):
        self.register()
        for other, peer in (("10:00:00:00:00:04", "10.23.0.53"),
                            ("10:00:00:00:00:06", "10.23.0.54"),
                            ("10:00:00:00:00:0a", "10.23.0.55")):
            self.cameras.devices[other] = {"model": "TD21", "last_ip": peer}
            params = copy.deepcopy(self.params)
            info = params["general_camera_manage"]["storage_info"]
            info["mac"] = other
            info["basic_info"]["ipaddr"] = peer
            with patch("native_storage.os.path.ismount", return_value=True), \
                    patch("native_storage.os.statvfs", return_value=SimpleNamespace(f_bavail=500_000_000, f_frsize=1)), \
                    patch("native_storage.threading.Thread"):
                result = self.storage.command(params, peer)
            self.assertEqual(result["error_code"], -40101 if peer.endswith("55") else 0)
        self.assertEqual(self.storage.public_list()["current_bound"], 3)

    def test_tc70_v5_registration_reports_one_continuous_recorder(self):
        self.cameras.devices[self.mac].update(model='TC70', hardware_version='5.0')
        self.params['general_camera_manage']['storage_info']['basic_info']['model'] = 'TC70'
        self.register()
        listing = self.storage.public_list()
        self.assertEqual(listing['max_24h_record_dev'], 1)
        self.assertEqual(listing['cur_24h_record_dev'], 1)
        self.assertTrue(listing['paired_general_device_list'][0]['plan_24h_record'])
        self.assertEqual(self.storage.devices[self.mac]['recording_mode'], 'continuous_lan')

    def test_native_storage_off_frees_slot_without_deleting_recording_history(self):
        self.register()
        result = self.storage.command({"general_camera_manage": {"storage_info": {
            "mac": self.mac, "enabled": "off"}}}, "10.23.0.52")
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(result["result"]["general_camera_manage"]["storage_info"]["storage_media_status"], 0)
        self.assertEqual(self.storage.public_list()["current_bound"], 0)
        self.assertIn(self.mac, self.storage.devices)


if __name__ == "__main__":
    unittest.main()
