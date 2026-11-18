import json
import unittest
from unittest.mock import patch

from camera_probe import CameraProbe, probe as run_probe, sha
from hub_lab import SetupAuth


class ProbeTests(unittest.TestCase):
    def test_verified_but_replaced_challenge_retries_once_with_fresh_nonce(self):
        auth = SetupAuth(sha("saved-password"))
        camera = CameraProbe("10.23.0.52", sha("saved-password"))
        challenges = []
        proof_count = 0
        def post(path, body):
            nonlocal proof_count
            params = json.loads(body)["params"]
            if "digest_passwd" not in params:
                challenges.append(params["cnonce"])
            else:
                proof_count += 1
                if proof_count == 1:
                    return {"error_code": -40413}
            return auth.login(params, "peer")
        with patch.object(camera, "_post", side_effect=post) as call:
            camera.login()
            self.assertEqual(call.call_count, 4)
        self.assertNotEqual(challenges[0], challenges[1])
        self.assertIsNotNone(camera.token)

    def test_challenge_retry_is_bounded_and_never_applies_to_other_errors(self):
        for code in (-40413, -40404):
            auth = SetupAuth(sha("saved-password"))
            camera = CameraProbe("10.23.0.52", sha("saved-password"))
            def post(path, body):
                params = json.loads(body)["params"]
                return {"error_code": code} if "digest_passwd" in params else auth.login(params, "peer")
            with patch.object(camera, "_post", side_effect=post) as call:
                with self.assertRaises(ValueError):
                    camera.login()
                self.assertEqual(call.call_count, 4 if code == -40413 else 2)

    def test_probe_passes_explicit_hub_ip_and_reads_scan_result(self):
        mac = "02:00:00:00:01:02"
        files = {
            "registry": json.dumps({"devices": {mac: {"last_ip": "10.23.0.60"}}}),
            "state": json.dumps({"password_hash": sha("secret")}),
            "/proc/net/arp": "IP address HW type Flags HW address Mask Device\n"
                             "10.23.0.60 0x1 0x2 02:00:00:00:01:02 * eth0\n",
        }
        scan_result = {"error_code": 0, "result": {"scan_status": "scanning", "hub_list": []}}
        with patch("camera_probe.Path.read_text", lambda path: files[str(path)]), \
                patch("camera_probe.CameraProbe", autospec=True) as client:
            camera = client.return_value
            camera.read.side_effect = [{"error_code": 0, "result": {
                "device_info": {"basic_info": {"mac": mac}}}}, {}, {}, scan_result]
            camera.scan_hubs.return_value = {"error_code": 0}
            result = run_probe(mac, "registry", "state", True, "10.23.0.72")
            camera.scan_hubs.assert_called_once_with("10.23.0.72")
            self.assertEqual(camera.read.call_args.args, ("getScanHubList",))
            self.assertEqual(result["hub_scan_result"], scan_result)

    def test_invalid_hub_target_stops_before_camera_access(self):
        with patch("camera_probe.CameraProbe") as camera:
            for scan, address in ((False, "10.23.0.72"), (True, "1.1.1.1"), (True, "tplink.com")):
                with self.assertRaises(ValueError):
                    run_probe("02:00:00:00:01:02", "missing", "missing", scan, address)
            camera.assert_not_called()

    def test_encrypted_reads_interoperate_with_hub_transport(self):
        auth = SetupAuth(sha("test-camera-secret"))
        probe = CameraProbe("10.23.0.60", auth.password_hash)
        methods = []

        def dispatch(request):
            self.assertEqual(request["method"], "multipleRequest")
            method = request["params"]["requests"][0]["method"]
            if method == "startScanHub":
                self.assertEqual(request["params"]["requests"][0]["params"], {
                    "hub_manage": {"start_scan_hub": {"unicast_hub_info": []}}})
            methods.append(method)
            return {"error_code": 0, "result": {"responses": [
                {"method": method, "error_code": 0, "result": {"test": method}}]}}

        def post(path, body, headers=None):
            if path == "/":
                response = auth.login(json.loads(body)["params"], "10.23.0.72")
                if response["error_code"] == 0:
                    old = response["result"]["stok"]
                    response["result"]["stok"] = "session~with!().punctuation"
                    auth.sessions[response["result"]["stok"]] = auth.sessions.pop(old)
                return response
            return auth.secure(path[6:-3], "10.23.0.72", body.encode(), headers, dispatch)

        with patch.object(probe, "_post", side_effect=post):
            probe.login()
            for method in ("getDeviceInfo", "getAppComponentList", "getHubStorage"):
                self.assertEqual(probe.read(method)["result"]["test"], method)
            with self.assertRaises(ValueError):
                probe.read("setHubStorage")
            self.assertEqual(probe.scan_hubs()["error_code"], 0)
        self.assertEqual(len(methods), 4)

    def test_wrong_camera_identity_stops_before_scanning(self):
        mac = "02:00:00:00:01:02"
        files = {
            "registry": json.dumps({"devices": {mac: {"last_ip": "10.23.0.60"}}}),
            "state": json.dumps({"password_hash": sha("secret")}),
            "/proc/net/arp": "IP address HW type Flags HW address Mask Device\n"
                             "10.23.0.60 0x1 0x2 02:00:00:00:01:02 * eth0\n",
        }
        with patch("camera_probe.Path.read_text", lambda path: files[str(path)]), \
                patch("camera_probe.CameraProbe.login"), \
                patch("camera_probe.CameraProbe.scan_hubs") as scan, \
                patch("camera_probe.CameraProbe.read", return_value={"error_code": 0, "result": {
                    "device_info": {"basic_info": {"mac": "02:00:00:00:01:03"}}}}) as read:
            with self.assertRaisesRegex(ValueError, "identity does not match"):
                run_probe(mac, "registry", "state", True)
            read.assert_called_once_with("getDeviceInfo")
            scan.assert_not_called()

    def test_rejects_mismatched_batch_response(self):
        probe = CameraProbe("10.23.0.60", sha("secret"))
        with patch.object(probe, "_request", return_value={"error_code": 0, "result": {
                "responses": [{"method": "setHubStorage", "error_code": 0}]}}):
            with self.assertRaisesRegex(ValueError, "batch response"):
                probe.read("getHubStorage")

    def test_password_mismatch_never_sends_login_proof(self):
        auth = SetupAuth(sha("different-password"))
        probe = CameraProbe("10.23.0.60", sha("hub-password"))
        with patch.object(probe, "_post", side_effect=lambda p, b: auth.login(json.loads(b)["params"], "peer")) as post:
            with self.assertRaisesRegex(ValueError, "no login proof sent"):
                probe.login()
            self.assertEqual(post.call_count, 1)
            self.assertIsNone(probe.token)

    def test_rejects_non_lan_and_bad_hash(self):
        for address, password in (("1.1.1.1", sha("test")), ("tplink.com", sha("test")),
                                  ("10.23.0.60", "plaintext")):
            with self.assertRaises(ValueError):
                CameraProbe(address, password)

    def test_unicast_scan_is_lan_only_and_never_binds(self):
        probe = CameraProbe("10.23.0.60", sha("secret"))
        with patch.object(probe, "_batch", return_value={"error_code": 0}) as batch:
            probe.scan_hubs("10.23.0.72")
            batch.assert_called_once_with("startScanHub", {"hub_manage": {
                "start_scan_hub": {"unicast_hub_info": [{"ipaddr": "10.23.0.72"}]}}})
            batch.reset_mock()
            with self.assertRaises(ValueError):
                probe.scan_hubs("1.1.1.1")
            batch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
