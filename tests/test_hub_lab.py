import base64
import hashlib
import json
import io
import struct
import time
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from hub_lab import SetupAuth, SetupCommands, Diagnostics, sha, decode_probe, encrypt_discovery, packet, setup_language, protocol_schema


class WireTests(unittest.TestCase):
    def test_large_authenticated_enrollment_reaches_authentication_with_bounded_body(self):
        auth = SetupAuth(sha("test-password"))
        peer = "192.0.2.2"
        auth.sessions["owned-session"] = {"peer": peer, "expires": time.monotonic()+60}
        raw = json.dumps({"method": "securePassthrough", "params": {"request": "A"*100_000}}).encode()
        for token, remote, expiry, expected in (
                ("owned-session", peer, 60, None),
                ("invalid", peer, 60, 413),
                ("owned-session", "192.0.2.3", 60, 413),
                ("owned-session", peer, -1, 413)):
            with self.subTest(token=token, remote=remote, expiry=expiry):
                auth.sessions["owned-session"]["expires"] = time.monotonic()+expiry
                handler = object.__new__(Diagnostics)
                handler.path = "/stok="+token+"/ds"
                handler.client_address = (remote, 123)
                handler.server = SimpleNamespace(auth=auth)
                handler.headers = {"Content-Length": str(len(raw))}
                handler.rfile, handler.wfile = io.BytesIO(raw), io.BytesIO()
                handler.send_error = Mock()
                handler.send_response = Mock()
                handler.send_header = Mock()
                handler.end_headers = Mock()
                auth.secure = Mock(return_value={"error_code": -40401})
                handler.do_POST()
                if expected:
                    handler.send_error.assert_called_once_with(expected)
                    auth.secure.assert_not_called()
                    self.assertEqual(handler.rfile.tell(), 0)
                else:
                    handler.send_error.assert_not_called()
                    auth.secure.assert_called_once()
                    self.assertEqual(json.loads(handler.wfile.getvalue())["error_code"], -40401)

    def test_camera_can_reauthenticate_on_old_session_url_without_bypassing_proof(self):
        auth = SetupAuth(sha("test-password"))
        peer = "192.0.2.2"
        def post(params):
            raw = json.dumps({"method": "login", "params": params}).encode()
            handler = object.__new__(Diagnostics)
            handler.client_address = (peer, 123)
            handler.server = SimpleNamespace(auth=auth)
            handler.path = "/stok=STALE/ds"
            handler.rfile, handler.wfile = io.BytesIO(raw), io.BytesIO()
            handler.headers = {"Content-Length": str(len(raw)), "Seq": "100", "Tapo_tag": "stale-tag"}
            handler.send_response = handler.send_header = handler.end_headers = Mock()
            handler.dispatch = Mock(side_effect=AssertionError("Login must never dispatch control commands"))
            handler.do_POST()
            handler.dispatch.assert_not_called()
            return json.loads(handler.wfile.getvalue())
        params = {"username": "admin", "cnonce": "FRESH-NONCE", "encrypt_type": "3"}
        nonce = post(params)["result"]["data"]["nonce"]
        self.assertFalse(auth.has_session(peer))
        self.assertNotEqual(post({**params, "digest_passwd": "wrong"})["error_code"], 0)
        nonce = post(params)["result"]["data"]["nonce"]
        proof = sha(auth.password_hash + "FRESH-NONCE" + nonce) + "FRESH-NONCE" + nonce
        self.assertEqual(post({"username": "admin", "encrypt_type": "3", "digest_passwd": proof})["error_code"], 0)
        self.assertTrue(auth.has_session(peer))
        self.assertNotEqual(post({"username": "admin", "encrypt_type": "3", "digest_passwd": proof})["error_code"], 0)

    def test_protocol_schema_does_not_log_credentials_or_identifiers(self):
        result = protocol_schema({"method": "register", "password": "private-password", "device_id": "private-id",
                                  "data": {"nonce": "private-nonce", "hub_password_list": ["private-hash"]}})
        encoded = json.dumps(result)
        self.assertNotIn("private-", encoded)
        self.assertEqual(result["method"], "register")
        self.assertEqual(result["password"], "redacted")
        self.assertEqual(result["data"]["nonce"], "redacted")

    def test_camera_login_proof_can_omit_cnonce_without_weakening_peer_or_proof_checks(self):
        auth = SetupAuth(sha("test-password"))
        peer = "192.0.2.2"
        first = auth.login({"username": "admin", "cnonce": "CAMERA-NONCE", "encrypt_type": "3"}, peer)
        server_nonce = first["result"]["data"]["nonce"]
        proof = sha(auth.password_hash + "CAMERA-NONCE" + server_nonce) + "CAMERA-NONCE" + server_nonce
        params = {"username": "admin", "encrypt_type": "3", "digest_passwd": proof}
        self.assertNotEqual(auth.login(params, "192.0.2.3")["error_code"], 0)
        self.assertNotEqual(auth.login({**params, "digest_passwd": "wrong"}, peer)["error_code"], 0)
        self.assertNotEqual(auth.login({**params, "cnonce": ""}, peer)["error_code"], 0)
        success = auth.login(params, peer)
        self.assertEqual(success["error_code"], 0)
        self.assertEqual(auth.sessions[success["result"]["stok"]]["nonce"], "CAMERA-NONCE")
        self.assertNotEqual(auth.login(params, peer)["error_code"], 0)  # The challenge is consumed.

    def test_connection_type_uses_the_app_ethernet_enum(self):
        handler = object.__new__(Diagnostics)
        handler.client_address = ("192.0.2.1", 123)
        self.assertEqual(handler.dispatch({"method": "getConnectionType", "params": {}}),
                         {"error_code": 0, "result": {"link_type": "ethernet"}})

    def test_camera_capacity_uses_tapo_camera_fields_in_authenticated_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            setup = SetupCommands(SetupAuth(), SimpleNamespace(bound=False), Path(directory)/"state.json")
            handler = object.__new__(Diagnostics)
            handler.client_address = ("192.0.2.1", 123)
            handler.server = SimpleNamespace(setup=setup)
            response = handler.dispatch({"method": "multipleRequest", "params": {"requests": [
                {"method": "getDeviceLoadInfo", "params": {"deviceLoad": {}}}]}})
            result = response["result"]["responses"][0]
            self.assertEqual(result["error_code"], 0)
            capacity = result["result"]
            # Android's DeviceLoadInfo defaults a missing primitive camera limit to zero.
            self.assertEqual(capacity["cam_max_load_num"], 16)
            self.assertEqual(capacity["cam_cur_load_num"], 0)
            self.assertEqual(capacity["cam_load_level"], "light")
            self.assertEqual(capacity["max_load_num"], 16)
            self.assertEqual(capacity["cur_load_num"], 0)

    def test_empty_paired_lists_and_update_preference(self):
        with tempfile.TemporaryDirectory() as directory:
            setup = SetupCommands(SetupAuth(), SimpleNamespace(bound=False), Path(directory)/"state.json")
            for method, key in (("getChildDeviceList", "child_device_list"),
                                ("getChildDeviceComponentList", "child_component_list")):
                result = setup.command(method, {"childControl": {"start_index": 0}})
                self.assertEqual(result["error_code"], 0)
                self.assertEqual(result["result"], {key: [], "start_index": 0, "sum": 0})
                self.assertNotEqual(setup.command(method, {"childControl": {"start_index": -1}})["error_code"], 0)
            self.assertEqual(setup.command("getDeviceLoadInfo", {})["result"]["cur_load_num"], 0)
            self.assertEqual(setup.command("getSupportChildDeviceCategory", {})["result"]["device_category_list"],
                             [{"category": "ipcamera"}])
            preference = {"auto_upgrade": {"common": {"enabled": "off", "time": "04:30"}}}
            self.assertEqual(setup.command("setFirmwareAutoUpgradeConfig", preference)["error_code"], 0)
            self.assertEqual(setup.command("getFirmwareAutoUpgradeConfig", {})["result"]["auto_upgrade"]["common"]["time"], "04:30")
            preference["auto_upgrade"]["common"]["time"] = "25:90"
            self.assertNotEqual(setup.command("setFirmwareAutoUpgradeConfig", preference)["error_code"], 0)

    def test_name_configuration_and_firmware_status_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            cloud = SimpleNamespace(bound=False)
            path = Path(directory)/"state.json"
            setup = SetupCommands(SetupAuth(), cloud, path, local_only=True)
            handler = object.__new__(Diagnostics)
            handler.client_address = ("192.0.2.1", 123)
            handler.server = SimpleNamespace(setup=setup, device_info={})
            result = handler.dispatch({"method": "multipleRequest", "params": {"requests": [
                {"method": "setDeviceAlias", "params": {"system": {"sys": {"dev_alias": "My Home Hub"}}}},
                {"method": "getDeviceInfo", "params": {}},
                {"method": "getFirmwareUpdateStatus", "params": {}}]}})
            responses = result["result"]["responses"]
            self.assertTrue(all(r["error_code"] == 0 for r in responses))
            self.assertEqual(responses[1]["result"]["device_info"]["basic_info"]["device_alias"], "My Home Hub")
            self.assertEqual(responses[2]["result"]["cloud_config"]["upgrade_status"]["state"], "normal")
            fresh = SetupCommands(SetupAuth(), cloud, path)
            self.assertEqual(fresh.state["device_alias"], "My Home Hub")
            for alias in (None, "", " ", "x" * 129, "name\n", "😀" * 33):
                response = fresh.command("setDeviceAlias", {"system": {"sys": {"dev_alias": alias}}})
                self.assertNotEqual(response["error_code"], 0)
            self.assertEqual(fresh.state["device_alias"], "My Home Hub")

    def test_local_association_never_calls_cloud_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            def forbidden(*_):
                self.fail("local mode attempted cloud registration")
            cloud = SimpleNamespace(bound=False, bind=forbidden)
            path = Path(directory)/"state.json"
            setup = SetupCommands(SetupAuth(), cloud, path, local_only=True)
            self.assertFalse(setup.associated)
            params = {"cloud_config": {"bind": {
                "username": "test@example.invalid", "password": "not-for-persistence"}}}
            self.assertEqual(setup.command("bindToCloud", params)["error_code"], 0)
            self.assertTrue(setup.associated)
            self.assertFalse(cloud.bound)
            fresh = SetupCommands(SetupAuth(), cloud, path, local_only=True)
            self.assertTrue(fresh.associated)
            self.assertEqual(fresh.state["binding_mode"], "local")
            self.assertNotIn("not-for-persistence", path.read_text())
            self.assertNotIn("test@example.invalid", path.read_text())
            params["cloud_config"]["bind"]["username"] = "different@example.invalid"
            self.assertNotEqual(fresh.command("bindToCloud", params)["error_code"], 0)
            # Local account association must not claim an external connection.
            status = fresh.command("getCloudConfig", {})
            self.assertEqual(status["result"]["cloud_config"]["device_status"]["status"], "disconnected")

    def test_setup_commands_and_password_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = SetupAuth()
            cloud = SimpleNamespace(bound=False, bind=lambda *_: False)
            path = Path(directory) / "state.json"
            setup = SetupCommands(auth, cloud, path)
            timezone = {"system": {"basic": {"timezone": "UTC+00:00", "zone_id": "Europe/Lisbon"}}}
            self.assertEqual(setup.command("setTimezone", timezone)["error_code"], 0)
            self.assertEqual(setup.command("getTimezone", {})["result"]["system"]["basic"]["zone_id"], "Europe/Lisbon")
            self.assertEqual(setup.command("setMediaEncrypt", {"cet": {"media_encrypt": {"enabled": "on"}}})["error_code"], 0)
            old = auth.password_hash
            change = {"user_management": {"change_admin_password": {
                "username": "admin", "secname": "root", "encrypt_type": "3",
                "old_passwd": old, "passwd": sha("new-test-password")}}}
            self.assertEqual(setup.command("changeAdminPassword", change)["error_code"], 0)
            fresh = SetupAuth()
            SetupCommands(fresh, cloud, path)
            self.assertEqual(fresh.password_hash, sha("new-test-password"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(setup.command("changeAdminPassword", change)["error_code"], 0)
            self.assertNotIn("new-test-password", path.read_text())
            self.assertEqual(setup.command("getBindStatus", {})["result"]["cloud_status"]["bind"]["status"], "unbound")

    def test_failed_binding_does_not_change_setup_password(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = SetupAuth()
            cloud = SimpleNamespace(bound=False, bind=lambda *_: False)
            handler = object.__new__(Diagnostics)
            handler.client_address = ("192.0.2.1", 123)
            handler.server = SimpleNamespace(setup=SetupCommands(auth, cloud, Path(directory)/"state.json"))
            old = auth.password_hash
            result = handler.dispatch({"method": "multipleRequest", "params": {"requests": [
                {"method": "bindToCloud", "params": {"cloud_config": {"bind": {
                    "username": "test@example.invalid", "password": "test"}}}},
                {"method": "changeAdminPassword", "params": {"user_management": {"change_admin_password": {
                    "username": "admin", "secname": "root", "encrypt_type": "3",
                    "old_passwd": old, "passwd": sha("new-password")}}}}]}})
            self.assertTrue(all(r["error_code"] != 0 for r in result["result"]["responses"]))
            self.assertEqual(auth.password_hash, old)

    def test_setup_language_stores_valid_value(self):
        state = {}
        self.assertEqual(setup_language({"language": "en_US"}, state)["error_code"], 0)
        self.assertEqual(state["language"], "en_US")
        self.assertEqual(setup_language({"language": "english"}, state)["error_code"], 0)
        for invalid in (None, {}, {"language": 12}, {"language": "../etc"}):
            self.assertNotEqual(setup_language(invalid, state)["error_code"], 0)
        self.assertEqual(state["language"], "english")

    def test_setup_handshake_and_secure_request(self):
        # Client formulas match python-kasa SslAesTransport, independently of sha().
        def digest(value):
            return hashlib.sha256(value.encode()).hexdigest().upper()
        auth = SetupAuth()
        peer = "192.0.2.1"
        nonce = "0123456789ABCDEF"
        params = {"username": "admin", "cnonce": nonce, "encrypt_type": "3"}
        challenge = auth.login(params, peer)["result"]["data"]
        server = challenge["nonce"]
        password_hash = digest(base64.b64decode("VFBMMDc1NTI2NDYwNjAz").decode())
        seed = digest(nonce + password_hash + server)
        self.assertEqual(challenge["device_confirm"], seed + server + nonce)
        proof = digest(password_hash + nonce + server) + nonce + server
        params["digest_passwd"] = proof
        self.assertNotEqual(auth.login(params, "192.0.2.2")["error_code"], 0)
        result = auth.login(params, peer)["result"]
        token = result["stok"]
        self.assertTrue(auth.has_session(peer))
        self.assertFalse(auth.has_session("192.0.2.2"))
        self.assertNotEqual(auth.login(params, peer)["error_code"], 0)
        key = bytes.fromhex(digest("lsk" + nonce + server + seed))[:16]
        iv = bytes.fromhex(digest("ivb" + nonce + server + seed))[:16]
        inner = json.dumps({"method": "getDeviceInfo"}).encode()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(inner) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        raw = json.dumps({"method": "securePassthrough", "params": {
            "request": base64.b64encode(encrypted).decode()}}).encode()
        # The official app advances its counter beyond start_seq, including gaps.
        tag = digest(digest(password_hash + nonce) + raw.decode() + "104")
        headers = {"Seq": "104", "Tapo_tag": tag}
        dispatch = lambda request: {"error_code": 0, "result": {"method": request["method"]}}
        self.assertNotEqual(auth.secure(token, peer, raw, {**headers, "Tapo_tag": "bad"}, dispatch)["error_code"], 0)
        response = auth.secure(token, peer, raw, headers, dispatch)
        self.assertEqual(response["seq"], 104)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        data = base64.b64decode(response["result"]["response"])
        padded = decryptor.update(data) + decryptor.finalize()
        unpad = padding.PKCS7(128).unpadder()
        decoded = json.loads(unpad.update(padded) + unpad.finalize())
        self.assertEqual(decoded["result"]["method"], "getDeviceInfo")
        self.assertNotEqual(auth.secure(token, peer, raw, headers, dispatch)["error_code"], 0)
        older_tag = digest(digest(password_hash + nonce) + raw.decode() + "103")
        self.assertEqual(auth.secure(token, peer, raw,
                            {"Seq": "103", "Tapo_tag": older_tag}, dispatch)["error_code"], 0)
        # A valid out-of-order request is accepted once, but never replayed.
        self.assertNotEqual(auth.secure(token, peer, raw,
                            {"Seq": "103", "Tapo_tag": older_tag}, dispatch)["error_code"], 0)
        # Changing the device password must not alter keys/signatures of an existing session.
        auth.password_hash = sha("changed-password")
        next_tag = digest(digest(password_hash + nonce) + raw.decode() + "105")
        self.assertEqual(auth.secure(token, peer, raw,
                         {"Seq": "105", "Tapo_tag": next_tag}, dispatch)["error_code"], 0)
        future_tag = digest(digest(password_hash + nonce) + raw.decode() + "300")
        self.assertEqual(auth.secure(token, peer, raw,
                         {"Seq": "300", "Tapo_tag": future_tag}, dispatch)["error_code"], 0)
        stale_tag = digest(digest(password_hash + nonce) + raw.decode() + "102")
        self.assertNotEqual(auth.secure(token, peer, raw,
                         {"Seq": "102", "Tapo_tag": stale_tag}, dispatch)["error_code"], 0)

    def test_header_and_crc(self):
        data = packet({"params": {}}, b"TEST")
        self.assertEqual(data[8:12], b"TEST")
        self.assertEqual(decode_probe(data), {"params": {}})
        damaged = bytearray(data)
        damaged[-1] ^= 1
        with self.assertRaises(ValueError):
            decode_probe(damaged)
        with self.assertRaises(ValueError):
            decode_probe(data[:15])

    def test_encrypted_discovery_interoperability(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_bytes(serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        result = encrypt_discovery(public, {"owner": "", "http_port": 443})
        material = key.decrypt(base64.b64decode(result["key"]), rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
        decryptor = Cipher(algorithms.AES(material[:16]), modes.CBC(material[16:])).decryptor()
        plain = decryptor.update(base64.b64decode(result["data"])) + decryptor.finalize()
        unpad = padding.PKCS7(128).unpadder()
        self.assertIn(b'"http_port": 443', unpad.update(plain) + unpad.finalize())


if __name__ == "__main__":
    unittest.main()
