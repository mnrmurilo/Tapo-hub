from types import SimpleNamespace
import unittest

from hub_lab import Diagnostics
from playback_clock import dst_status


class PlaybackClockTests(unittest.TestCase):
    def test_local_rules_match_native_camera_format_and_offsets(self):
        for zone in ("Europe/London", "Europe/Lisbon"):
            self.assertEqual(dst_status(zone), {
                "enabled": "1", "synced": "1", "has_rule": "1",
                "dst_rule": "DST-01:00,M3.5.0/01:00:00,M10.5.0/02:00:00"})
        self.assertEqual(dst_status("America/New_York")["dst_rule"],
                         "DST-01:00,M3.2.0/02:00:00,M11.1.0/02:00:00")
        self.assertEqual(dst_status("Etc/UTC")["has_rule"], "0")
        self.assertEqual(dst_status("Australia/Lord_Howe")["dst_rule"],
                         "DST-00:30,M10.1.0/02:00:00,M4.1.0/02:00:00")

    def test_face_player_initialization_batch_has_no_failed_subrequest(self):
        handler = object.__new__(Diagnostics)
        handler.client_address = ("192.0.2.1", 1234)
        handler.server = SimpleNamespace(setup=SimpleNamespace(
            state={"zone_id": "Europe/London", "timezone": "UTC-00:00"},
            command=lambda method, params: {"error_code": 0, "result": {}}))
        reply = handler.dispatch({"method": "multipleRequest", "params": {"requests": [
            {"method": method, "params": {"system": {"name": name}}}
            for method, name in (("getClockStatus", "clock_status"),
                                 ("getDstRule", "dst"), ("getTimezone", "basic"))]}})
        self.assertTrue(all(item["error_code"] == 0 for item in reply["result"]["responses"]))
        self.assertEqual(reply["result"]["responses"][1]["result"]["system"]["dst"]["has_rule"], "1")

    def test_invalid_zone_never_reads_arbitrary_paths(self):
        for zone in ("/etc/passwd", "../../etc/passwd"):
            with self.assertRaises(ValueError):
                dst_status(zone)
