import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hub_lab import Diagnostics
from storage_status import STORE, command, disk_info


class StorageStatusTests(unittest.TestCase):
    def setUp(self):
        self.mount = patch("storage_status.os.path.ismount", return_value=True).start()
        patch("storage_status.os.path.isfile", return_value=True).start()
        self.access = patch("storage_status.os.access", return_value=True).start()
        self.device = patch("storage_status.os.stat", side_effect=lambda path: SimpleNamespace(st_dev=1 if str(path) == "/" else 2)).start()
        self.usage = SimpleNamespace(f_blocks=24_000_000, f_bavail=23_000_000, f_frsize=4096, f_flag=0)
        self.stat = patch("storage_status.os.statvfs", return_value=self.usage).start()
        self.addCleanup(patch.stopall)
        self.query = {"harddisk_manage": {"table": ["hd_info"]}}

    def test_real_filesystem_capacity_and_available_space_are_read_each_time(self):
        info = command(self.query)["result"]["harddisk_manage"]["hd_info"][0]["hd_info_1"]
        self.assertEqual(info["status"], "normal")
        self.assertEqual(float(info["total_space"].removesuffix("MB")) * 1048576, 98_304_000_000)
        self.assertEqual(float(info["free_space"].removesuffix("MB")) * 1048576, 94_208_000_000)
        self.usage.f_bavail -= 1_000_000
        self.assertNotEqual(disk_info()["free_space"], info["free_space"])
        self.stat.assert_called_with(STORE)

    def test_missing_mount_never_reports_container_root_capacity(self):
        self.mount.return_value = False
        info = disk_info()
        self.assertEqual(info["status"], "offline")
        self.assertEqual(info["total_space"], "0.000000MB")
        self.stat.assert_not_called()

    def test_container_root_filesystem_is_not_exposed(self):
        self.device.side_effect = lambda path: SimpleNamespace(st_dev=1)
        self.assertEqual(disk_info()['status'], 'abnormal')
        self.assertEqual(disk_info()['total_space'], '0.000000MB')

    def test_read_only_full_and_io_error_states(self):
        self.access.return_value = False
        self.assertEqual(disk_info()["status"], "abnormal")
        self.assertEqual(disk_info()["write_protect"], "1")
        self.access.return_value = True
        self.usage.f_flag = os.ST_RDONLY
        self.assertEqual(disk_info()["rw_attr"], "r")
        self.usage.f_flag = 0
        self.usage.f_bavail = 0
        self.assertEqual(disk_info()["status"], "full")
        self.stat.side_effect = OSError("unavailable")
        self.assertEqual(disk_info()["status"], "abnormal")
        self.assertEqual(disk_info()["total_space"], "0.000000MB")

    def test_invalid_or_path_supplied_queries_do_not_touch_disk(self):
        for query in (None, [], {}, {"harddisk_manage": {"table": ["/unrelated-data"]}},
                      {"harddisk_manage": {"table": ["hd_info"], "path": "/tmp"}}):
            self.assertNotEqual(command(query)["error_code"], 0)
        self.stat.assert_not_called()

    def test_authenticated_dispatch_supports_both_storage_reads_and_no_format(self):
        handler = object.__new__(Diagnostics)
        handler.client_address = ("192.0.2.1", 1234)
        for method in ("getHardDiskStatus", "getSdCardStatus"):
            response = handler.dispatch({"method": method, "params": self.query})
            self.assertEqual(response["error_code"], 0)
            self.assertEqual(response["result"]["harddisk_manage"]["hd_info"][0]["hd_info_1"]["status"], "normal")
        for method in ("formatHardDisk", "formatSdCard", "removeHardDiskChildRecord"):
            self.assertEqual(handler.dispatch({"method": method, "params": self.query})["error_code"], -40210)
        components = handler.dispatch({"method": "getAppComponentList"})["result"]["app_component"]["app_component_list"]
        self.assertIn({"name": "hardDisk", "version": 1}, components)
        self.assertTrue(any(item["name"] == "hubRecord" for item in components))
        self.assertEqual(handler.dispatch({"method": "getCircularRecordingConfig"})["result"],
                         {"harddisk_manage": {"harddisk": {"loop": "off"}}})
        self.assertEqual(handler.dispatch({"method": "getScaleList"})["result"],
                         {"playback": {"scale_capability": []}})


if __name__ == "__main__":
    unittest.main()
