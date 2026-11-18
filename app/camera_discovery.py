"""Camera-to-hub discovery only; never enrolls cameras or enables storage."""
import hmac
import ipaddress
import logging
import socket
import threading
import time

from camera_registry import LAN, normalize_mac, camera_supported
from camera_probe import CameraProbe
from native_storage import MAX_BOUND

LOG = logging.getLogger("tapo-hub-lab")


def respond(raw, peer_ip, hub_ip, device_info, setup, registry, encode, decode):
    if ipaddress.IPv4Address(peer_ip) not in LAN:
        return None
    request = decode(raw, expected_opcode=4)
    # The observed request is a version-2 camera hub scan, not generic app discovery.
    if raw[1] != 0 or raw[6:8] != b"\x21\x01":
        raise ValueError("Unsupported camera discovery flags")
    params = request.get("params", {})
    mac = normalize_mac(params.get("mac"))
    owner = params.get("owner")
    expected_owner = setup.state.get("owner")
    if not isinstance(owner, str) or not expected_owner or not hmac.compare_digest(owner.upper(), expected_owner.upper()):
        return None
    with registry.lock:
        known = registry.devices.get(mac)
        if known is None or not camera_supported(known):
            return None
        model = params.get("device_model", "").split("(")[0].upper()
        if {"D210": "TD21"}.get(model, model) != known["model"]:
            return None
    if params.get("ip") != peer_ip or params.get("auth_type") != "SHA256":
        return None
    LOG.info("CAMERA HUB DISCOVERY request_fields=%s param_fields=%s capability_flags=%s", sorted(request), sorted(params),
             {key: value for key, value in params.items() if key in
              ("hub_cam_capability", "hub_storage", "wifi_backup", "ai_camera_support") and type(value) in (int, bool)})
    # Discovery is an unauthenticated observation, not an enrollment or online guarantee.
    registry.observe(params, peer_ip, hub_scan=True)
    hub_mac = normalize_mac(device_info["mac"]).replace(":", "").upper()
    alias = setup.state.get("device_alias", "Tapo Hub")
    result = {
        "ip": hub_ip, "ipaddr": hub_ip, "mac": hub_mac,
        "device_id": device_info["dev_id"], "device_type": "SMART.TAPOHUB",
        "device_model": device_info["device_model"], "device_name": alias,
        "type": "SMART.TAPOHUB", "model": device_info["device_model"], "alias": alias,
        "owner": expected_owner, "bind_sta": "bound", "auth_type": "SHA256",
        "current_bound": 0, "max_bound": MAX_BOUND, "ai_hub_support": 0,
        # Native recording activation is unfinished; disk capacity is reported separately.
        "storage_media_status": 0, "hub_storage": 0, "wifi_backup": 0,
        "network_mode": "wired",
    }
    return encode({"error_code": 0, "result": result}, raw[8:12], opcode=4, flags=0x22, reserved=1)


def serve(stream, hub_ip, device_info, setup, registry, encode, decode):
    LOG.info("CAMERA HUB DISCOVERY listening UDP=20015; registration handled by native storage")
    last_reply = {}
    while True:
        raw, peer = stream.recvfrom(8193)
        try:
            now = time.monotonic()
            last_reply = {ip: stamp for ip, stamp in last_reply.items() if now - stamp < 10}
            if now - last_reply.get(peer[0], -10) < 0.25:
                continue
            reply = respond(raw, peer[0], hub_ip, device_info, setup, registry, encode, decode)
            if reply is not None:
                stream.sendto(reply, peer)
                last_reply[peer[0]] = now
                LOG.info("CAMERA HUB DISCOVERY peer=%s request_opcode=4 response_sent=True", peer[0])
        except (ValueError, TypeError, AttributeError, KeyError, OSError):
            LOG.info("CAMERA HUB DISCOVERY rejected malformed/unsupported request peer=%s bytes=%d", peer[0], len(raw))


def start(hub_ip, device_info, setup, registry, encode, decode):
    stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stream.bind(("0.0.0.0", 20015))
    threading.Thread(target=serve, args=(stream, hub_ip, device_info, setup, registry, encode, decode),
                     daemon=True).start()


def command(method, params, registry, now=None, scan=None, native=None):
    """Expose supported discovery candidates, separately from enrolled devices."""
    section = params.get("general_camera_manage") if isinstance(params, dict) else None
    expected = {"startScanGeneralDevice": "start_scan", "stopScanGeneralDevice": "stop_scan",
                "getScanGeneralDeviceList": "general_device_list",
                "getGeneralDeviceList": "paired_general_device_list"}.get(method)
    if expected is None:
        return {"error_code": -40210}
    if not isinstance(section, dict) or set(section) != {expected} or section[expected] != {}:
        return {"error_code": -40209}
    if method in ("startScanGeneralDevice", "stopScanGeneralDevice"):
        if scan is not None:
            scan.begin() if method == "startScanGeneralDevice" else scan.stop.set()
        return {"error_code": 0, "result": {}}
    if method == "getGeneralDeviceList":
        if native is not None:
            return {"error_code": 0, "result": {"general_camera_manage": native.public_list()}}
        return {"error_code": 0, "result": {"general_camera_manage": {
            "max_bound": MAX_BOUND, "current_bound": 0, "max_24h_record_dev": 1,
            "cur_24h_record_dev": 0, "paired_general_device_list": []}}}
    now = time.time() if now is None else now
    candidates = []
    with registry.lock:
        for mac, record in registry.devices.items():
            observed = record.get("hub_discovery", {})
            age = now - observed.get("last_seen", 0)
            if not camera_supported(record) or not observed or not 0 <= age <= 600:
                continue
            candidates.append({"mac": mac.replace(":", "").upper(), "device_model": record["model"],
                "device_type": observed["device_type"], "alias": observed["alias"],
                "ipaddr": observed["ipaddr"], "network_mode": observed["network_mode"],
                # Protocol 1004 selects the storage path with Wi-Fi backup unavailable.
                # Admission/enrollment still requires a successful native storageHubRequest.
                "category": "camera", "bind_check": 1004})
    status = "scanning" if scan is not None and scan.running and not scan.stop.is_set() else "idle"
    return {"error_code": 0, "result": {"general_camera_manage": {"scan_status": status,
        "general_device_list": candidates, "unsupported_device_list": []}}}


class LocalScan:
    """One bounded, read-only scan of supported cameras initiated from the app."""
    def __init__(self, registry, hub_ip, setup):
        self.registry, self.hub_ip, self.setup = registry, hub_ip, setup
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.running = False
        self.thread = None

    def begin(self):
        with self.lock:
            if self.running:
                return
            self.running = True
            self.stop.clear()
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

    def _run(self):
        try:
            with self.registry.lock:
                pending = {mac: dict(record) for mac, record in self.registry.devices.items() if camera_supported(record)}
            deadline = time.monotonic() + 20
            while pending and not self.stop.is_set() and time.monotonic() < deadline:
                for mac, known in list(pending.items()):
                    if self.stop.is_set() or time.monotonic() >= deadline:
                        break
                    address = self.registry.resolve(mac)
                    if address is None:
                        continue
                    try:
                        with socket.create_connection((address, 443), timeout=0.6):
                            pass
                    except OSError:
                        continue
                    pending.pop(mac)
                    try:
                        camera = CameraProbe(address, self.setup.auth.password_hash)
                        camera.login()
                        info = camera.read("getDeviceInfo")
                        basic = info.get("result", {}).get("device_info", {}).get("basic_info", {})
                        if info.get("error_code") != 0 or normalize_mac(basic.get("mac")) != mac or basic.get("device_model") != known["model"]:
                            continue
                        response = camera.scan_hubs(self.hub_ip)
                        LOG.info("CAMERA APP SCAN model=%s discovery_requested=%s", known["model"], response.get("error_code") == 0)
                    except (OSError, ValueError, TypeError, KeyError):
                        LOG.info("CAMERA APP SCAN model=%s unavailable; no settings changed", known["model"])
                if pending:
                    self.stop.wait(1)
            if not self.stop.is_set():
                self.stop.wait(2)
        except (OSError, ValueError, TypeError, KeyError):
            LOG.info("CAMERA APP SCAN unavailable; no camera settings changed")
        finally:
            with self.lock:
                self.running = False
