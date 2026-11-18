"""Persistent native camera associations; recording reception is tracked separately."""
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import threading
import time

from camera_registry import LAN, normalize_mac, camera_supported
from camera_media import STORE
from storage_status import disk_info

LOG = logging.getLogger("tapo-hub-lab")
# The app rechecks free admission slots when enabling storage on an associated camera.
MAX_BOUND = 3
# The firmware's native upload path rejects storage_media_status=0 as unavailable.
STORAGE_MEDIA_READY = 1


class NativeStorage:
    def __init__(self, path, cameras, setup, device_info):
        self.path = Path(path)
        self.cameras, self.setup, self.device_info = cameras, setup, device_info
        self.lock = threading.RLock()
        self.devices = json.loads(self.path.read_text()) if self.path.exists() else {}
        if not isinstance(self.devices, dict):
            raise ValueError("Invalid native camera registry")
        for mac, record in self.devices.items():
            if normalize_mac(mac) != mac or not isinstance(record, dict) or not camera_supported(record):
                raise ValueError("Invalid enrolled camera identity")

    def _save(self, devices):
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".enrolled-")
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(devices, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            self.devices = devices
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def public_list(self):
        with self.lock:
            entries = [{key: record[key] for key in (
                "device_id", "device_model", "device_type", "alias", "mac", "ip_addr",
                "network_mode", "parent_device_id", "category", "hub_storage_enabled",
                "wifi_backup_enabled", "plan_24h_record", "general_camera", "local_online",
                "ai_camera_support", "backup_wifi")}
                for record in self.devices.values()
                if record.get("hub_storage_enabled") or record.get("wifi_backup_enabled")]
        return {"max_bound": MAX_BOUND, "current_bound": len(entries), "max_24h_record_dev": 1,
                "cur_24h_record_dev": sum(bool(row["plan_24h_record"]) for row in entries),
                "paired_general_device_list": entries}

    def command(self, params, peer):
        stage = "request"
        try:
            if ipaddress.IPv4Address(peer) not in LAN:
                return {"error_code": -40401}
            info = params["general_camera_manage"]["storage_info"]
            mac = normalize_mac(info["mac"])
            enabled = info["enabled"]
            with self.cameras.lock:
                known = self.cameras.devices.get(mac)
                if known is None or not camera_supported(known) or known.get("last_ip") != peer:
                    return {"error_code": -40401}
            if enabled not in ("on", "off"):
                raise ValueError("Invalid storage setting")
            with self.lock:
                previous = self.devices.get(mac)
                if enabled == "off":
                    if previous:
                        self._save({**self.devices, mac: {**previous, "hub_storage_enabled": False}})
                    return {"error_code": 0, "result": {"general_camera_manage": {"storage_info": {
                        "storage_media_status": 0, "hub_cam_capability": 0}}}}
                if known['model'] == 'TC70' and known.get('continuous') is not True:
                    # TC70 reception requires an explicitly configured continuous recorder.
                    return {"error_code": -40210}
                if sum(other != mac and bool(record.get("hub_storage_enabled") or record.get("wifi_backup_enabled"))
                       for other, record in self.devices.items()) >= MAX_BOUND:
                    return {"error_code": -40101}
                basic = info["basic_info"]
                stage = "camera_identity"
                identity = basic["device_id"]
                if basic["model"] != known["model"] or basic["ipaddr"] != peer or not re.fullmatch(r"[A-Fa-f0-9]{40}", identity):
                    raise ValueError("Camera identity mismatch")
                if previous and previous["device_id"] != identity:
                    return {"error_code": -40401}
                stage = "camera_type"
                if not isinstance(basic["type"], str) or not basic["type"].startswith("SMART.") or len(basic["type"]) > 64:
                    raise ValueError("Invalid camera type")
                alias = basic["alias"]
                stage = "camera_alias"
                if not isinstance(alias, str) or len(alias.encode()) > 128:
                    raise ValueError("Invalid camera alias")
                stage = "binding_token"
                bind_code = info["bind_code"]
                # Native binding tokens are opaque strings, not necessarily UUIDs.
                if not isinstance(bind_code, str) or not 1 <= len(bind_code) <= 128 or any(
                        not 33 <= ord(char) <= 126 for char in bind_code):
                    raise ValueError("Invalid binding token")
                stage = "recording_store"
                if not os.path.ismount(STORE) or os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize < 120_000_000:
                    return {"error_code": -40101}
                if disk_info()["status"] != "normal":
                    return {"error_code": -40101}
                stage = "registration_record"
                record = {"device_id": identity, "device_model": known["model"], "hardware_version": known.get("hardware_version", ""), "device_type": basic["type"],
                    "alias": alias, "mac": mac.replace(":", "").upper(), "ip_addr": peer,
                    "network_mode": basic.get("network_mode", "wireless"), "category": "camera",
                    "parent_device_id": self.device_info["dev_id"], "hub_storage_enabled": True,
                    "wifi_backup_enabled": False, "plan_24h_record": known["model"] == "TC70", "general_camera": 1,
                    "ai_camera_support": basic.get("ai_camera_support", 0), "backup_wifi": "",
                    "local_online": 1, "bind_code": bind_code, "registered_at": time.time(),
                    "recording_mode": "continuous_lan" if known["model"] == "TC70" else "persistent_native",
                    "restore_status": "not_scheduled",
                    "recording_status": "awaiting_continuous_segment" if known["model"] == "TC70" else "awaiting_native_event"}
                if previous and previous.get("bind_code") == bind_code:
                    record = {**previous, **record}
                self._save({**self.devices, mac: record})
            LOG.info("CAMERA ENROLLMENT persistent registration accepted model=%s; recording=unverified", known["model"])
            # The camera commits the destination MAC/IP only from basic_info.
            return {"error_code": 0, "result": {"general_camera_manage": {"storage_info": {
                "storage_media_status": STORAGE_MEDIA_READY, "hub_cam_capability": 0, "basic_info": {
                    "device_id": self.device_info["dev_id"],
                    "ipaddr": self.device_info["ipaddr"],
                    "model": self.device_info["device_model"],
                    "type": self.device_info["device_type"], "auth_type": "NONE",
                    "alias": self.setup.state.get("device_alias", "Tapo Hub"),
                    "mac": normalize_mac(self.device_info["mac"]).replace(":", "").upper(),
                    "hub_id": self.device_info["dev_id"][:8], "ai_hub_support": 0}}}}}
        except (ValueError, KeyError, TypeError, AttributeError):
            LOG.info("CAMERA ENROLLMENT invalid native registration stage=%s", stage)
            return {"error_code": -40209}
        except OSError:
            return {"error_code": -40101}

    def sync(self, params, peer):
        """Receive an enrolled camera's status without changing its detection settings."""
        try:
            info = params["general_camera_manage"]["config_sync"]
            mac = normalize_mac(info["mac"])
            basic = info["basic_info"]
            with self.cameras.lock:
                known = self.cameras.devices.get(mac, {})
                if not camera_supported(known) or known.get("last_ip") != peer:
                    return {"error_code": -40401}
            with self.lock:
                record = self.devices.get(mac)
                if (not record or basic.get("device_id") != record["device_id"]
                        or basic.get("model") != record["device_model"] or basic.get("model") != known["model"] or info.get("ip") != peer
                        or normalize_mac(info["storage_mac"]) != normalize_mac(self.device_info["mac"])):
                    return {"error_code": -40401}
                enabled = info["hub_storage_enabled"]
                if type(enabled) is not int or enabled not in (0, 1):
                    return {"error_code": -40209}
                if disk_info()["status"] != "normal":
                    return {"error_code": -40101}
                self._save({**self.devices, mac: {**record, "last_sync_at": time.time(),
                                                "ip_addr": peer,
                                                "camera_storage_enabled": bool(enabled)}})
            LOG.info("CAMERA SYNC accepted model=%s storage_enabled=%s", record["device_model"], bool(enabled))
            return {"error_code": 0, "result": {"general_camera_manage": {"config_sync": {
                "zone_id": self.setup.state.get("zone_id", "Etc/UTC"),
                "timezone": self.setup.state.get("timezone", "UTC+00:00"),
                "storage_media_status": STORAGE_MEDIA_READY, "hub_cam_capability": 0, "chn_num": 0,
                "ai_enhance_enabled": 0, "ALGbitmap": 0, "ai_hub_support": 0}}}}
        except (ValueError, TypeError, KeyError, AttributeError):
            return {"error_code": -40209}
        except OSError:
            return {"error_code": -40101}
