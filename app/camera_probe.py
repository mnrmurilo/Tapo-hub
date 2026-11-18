"""Read-only, LAN-only camera capability probe. Does not enable hub storage."""
import argparse
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import threading

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from camera_registry import LAN, normalize_mac


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest().upper()


READS = {
    "getDeviceInfo": {"device_info": {"name": "basic_info"}},
    "getAppComponentList": {"app_component": {"name": "app_component_list"}},
    "getHubStorage": {"hub_manage": {"name": "hub_storage_info"}},
    "getScanHubList": {"hub_manage": {"get_scan_hub_list": {}}},
}


class CameraProbe:
    _login_lock = threading.Lock()

    def __init__(self, address, password_hash, timeout=5):
        if ipaddress.IPv4Address(address) not in LAN:
            raise ValueError("Camera is outside the local network")
        if not isinstance(password_hash, str) or not re.fullmatch(r"[A-F0-9]{64}", password_hash):
            raise ValueError("Expected an existing SHA256 password hash")
        self.address, self.password_hash = address, password_hash
        self.timeout = timeout
        self.token = None

    def _post(self, path, body, headers=None):
        # Cameras use self-signed certificates. Verify device_confirm before sending proof.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(self.address, timeout=self.timeout, context=context)
        try:
            connection.request("POST", path, body, {
                "Content-Type": "application/json; charset=UTF-8", "requestByApp": "true",
                **(headers or {})})
            response = connection.getresponse()
            raw = response.read(262145)
            if response.status != 200 or len(raw) > 262144:
                raise ValueError("Camera returned an invalid HTTP response")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("Camera returned invalid JSON")
            return result
        finally:
            connection.close()

    def login(self):
        with self._login_lock:
            for _ in range(2):
                if self._login_once():
                    return
        raise ValueError("Camera challenge changed twice; authentication stopped")

    def _login_once(self):
        self.token = None
        self.nonce = os.urandom(8).hex().upper()
        params = {"username": "admin", "cnonce": self.nonce, "encrypt_type": "3"}
        response = self._post("/", json.dumps({"method": "login", "params": params}))
        data = response.get("result", {}).get("data", {})
        server_nonce = data.get("nonce")
        if not isinstance(server_nonce, str) or not re.fullmatch(r"[A-Fa-f0-9]{16}", server_nonce):
            raise ValueError("Camera did not offer a supported SSL/AES challenge")
        seed = sha(self.nonce + self.password_hash + server_nonce)
        confirm = data.get("device_confirm")
        if not isinstance(confirm, str) or not hmac.compare_digest(confirm, seed + server_nonce + self.nonce):
            # No proof is sent on mismatch: do not consume failed-password attempts.
            raise ValueError("Camera password differs from the saved hub credential; no login proof sent")
        params["digest_passwd"] = sha(self.password_hash + self.nonce + server_nonce) + self.nonce + server_nonce
        response = self._post("/", json.dumps({"method": "login", "params": params}))
        result = response.get("result", {})
        if response.get("error_code") == -40413:
            # The password was confirmed above; a concurrent login can replace this challenge.
            return False
        token, sequence = result.get("stok"), result.get("start_seq")
        if response.get("error_code") != 0 or not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@-]{1,128}", token) or type(sequence) is not int or not 0 <= sequence <= 0x7fffffff:
            code = response.get("error_code")
            raise ValueError("Camera rejected local authentication: " + json.dumps({
                "error_code": code if type(code) is int else None,
                "token_length": len(token) if isinstance(token, str) else None,
                "sequence_type": type(sequence).__name__}))
        self.token, self.sequence = token, sequence
        self.key = bytes.fromhex(sha("lsk" + self.nonce + server_nonce + seed))[:16]
        self.iv = bytes.fromhex(sha("ivb" + self.nonce + server_nonce + seed))[:16]
        return True

    def read(self, method):
        if method not in READS:
            raise ValueError("Only the fixed capability queries are allowed")
        return self._batch(method, READS[method])

    def scan_hubs(self, hub_ip=None):
        """Start discovery only; never select a hub or enable recording."""
        if hub_ip is not None and ipaddress.IPv4Address(hub_ip) not in LAN:
            raise ValueError("Hub is outside the local network")
        return self._batch("startScanHub", {"hub_manage": {
            "start_scan_hub": {"unicast_hub_info": [{"ipaddr": hub_ip}] if hub_ip else []}}})

    def _batch(self, method, params):
        response = self._request({"method": "multipleRequest", "params": {"requests": [
            {"method": method, "params": params}]}})
        if response.get("error_code") != 0:
            return response
        responses = response.get("result", {}).get("responses")
        if not isinstance(responses, list) or len(responses) != 1 or not isinstance(responses[0], dict) or responses[0].get("method") != method:
            raise ValueError("Invalid capability batch response")
        return responses[0]

    def _request(self, request):
        if self.token is None:
            raise ValueError("Authenticate before querying")
        request = json.dumps(request).encode()
        padder = padding.PKCS7(128).padder()
        plain = padder.update(request) + padder.finalize()
        encryptor = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)).encryptor()
        encrypted = encryptor.update(plain) + encryptor.finalize()
        body = json.dumps({"method": "securePassthrough", "params": {
            "request": base64.b64encode(encrypted).decode()}})
        sequence = self.sequence
        self.sequence += 1
        tag = sha(sha(self.password_hash + self.nonce) + body + str(sequence))
        response = self._post("/stok=" + self.token + "/ds", body,
                              {"Seq": str(sequence), "Tapo_tag": tag})
        if response.get("error_code") == 0 and "response" in response.get("result", {}):
            encrypted = base64.b64decode(response["result"]["response"], validate=True)
            decryptor = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)).decryptor()
            padded = decryptor.update(encrypted) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            response = json.loads(unpadder.update(padded) + unpadder.finalize())
        if not isinstance(response, dict):
            raise ValueError("Invalid capability response")
        return response


def probe(mac, registry_file, state_file, scan_hubs=False, hub_ip=None):
    if hub_ip is not None:
        if not scan_hubs:
            raise ValueError("A hub IP requires hub scanning")
        if ipaddress.IPv4Address(hub_ip) not in LAN:
            raise ValueError("Hub is outside the local network")
    mac = normalize_mac(mac)
    registry = json.loads(Path(registry_file).read_text())
    record = registry["devices"][mac]
    address = record.get("last_ip")
    if not address:
        raise ValueError("No observed address for this MAC")
    neighbors = Path("/proc/net/arp").read_text().splitlines()[1:]
    matched = False
    for line in neighbors:
        fields = line.split()
        if len(fields) >= 6 and fields[0] == address and int(fields[2], 16) & 2:
            matched = normalize_mac(fields[3]) == mac
            break
    if not matched:
        raise ValueError("Camera's current address does not match its configured MAC")
    password_hash = json.loads(Path(state_file).read_text())["password_hash"]
    camera = CameraProbe(address, password_hash)
    camera.login()
    info = camera.read("getDeviceInfo")
    basic = info.get("result", {}).get("device_info", {}).get("basic_info", {})
    if info.get("error_code") != 0 or normalize_mac(basic.get("mac")) != mac:
        raise ValueError("Authenticated camera identity does not match the configured MAC")
    # Whitelist output fields: never print raw authentication or account responses.
    report = {"mac": mac, "address": address, "device": {
        key: basic[key] for key in ("device_model", "hw_version", "sw_version") if key in basic},
        "components": camera.read("getAppComponentList"), "hub_storage": camera.read("getHubStorage")}
    if scan_hubs:
        report["hub_scan"] = camera.scan_hubs(hub_ip)
        if report["hub_scan"].get("error_code") == 0:
            report["hub_scan_result"] = camera.read("getScanHubList")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--registry", default="/var/lib/tapo-hub/cameras.json")
    parser.add_argument("--state", default="/var/lib/tapo-hub/state.json")
    parser.add_argument("--scan-hubs", action="store_true", help="Trigger hub discovery without changing recording settings")
    parser.add_argument("--hub-ip", help="Target this LAN hub address with --scan-hubs")
    args = parser.parse_args()
    if args.hub_ip and not args.scan_hubs:
        parser.error("--hub-ip requires --scan-hubs")
    try:
        print(json.dumps(probe(args.mac, args.registry, args.state, args.scan_hubs, args.hub_ip), indent=2))
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as error:
        # Don't print exception text from HTTP libraries (may contain session routes).
        print(json.dumps({"status": "probe_failed", "reason": str(error) if type(error) is ValueError else type(error).__name__}))
        raise SystemExit(1)
