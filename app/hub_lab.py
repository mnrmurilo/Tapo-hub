#!/usr/bin/env python3
"""Experimental Tapo hub setup; live cloud binding and camera storage are unverified.

Wire format references: python-kasa kasa/discover.py and aestransport.py,
and cB-Sigma/tplink-sim sim/smart.go (Apache-2.0).
H500 factory-default fields are hypotheses for testing, not captured H500 data.
"""
import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
import tempfile
import zlib
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tls_server import TLSHTTPServer, BoundedHTTPServer

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cloud_client import CloudClient
from camera_registry import CameraRegistry, watch_cameras
from camera_discovery import start as start_camera_discovery, command as camera_discovery_command, LocalScan
from native_storage import NativeStorage
from native_event_capture import NativeEventCapture
from recording_playback import RecordingPlayback, METHODS as PLAYBACK_METHODS
from playback_media import MediaAuth, PlaybackMedia, serve_playback
from recording_retention import activity, watch as watch_retention
from recording_observation import watch as watch_observation
from face_api import FaceAPI, METHODS as FACE_METHODS
from face_inference import FaceClient
from storage_status import command as storage_status_command
from playback_clock import dst_status

LOG = logging.getLogger("tapo-hub-lab")


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest().upper()


def protocol_schema(value, depth=0, key=""):
    """Bounded diagnostics: reveal structure and protocol enums, never credential values."""
    if any(word in key.lower() for word in ("pass", "secret", "token", "nonce", "digest", "key")):
        return "redacted"
    if depth >= 5:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k)[:64]: protocol_schema(v, depth + 1, str(k)) for k, v in list(value.items())[:24]}
    if isinstance(value, list):
        return {"count": len(value), "item": protocol_schema(value[0], depth + 1, key) if value else None}
    if key in ("method", "type", "action", "command", "version", "step", "request_type") and isinstance(value, (str, int)):
        if isinstance(value, int) or re.fullmatch(r"[A-Za-z0-9_-]{1,40}", value):
            return value
    return {"type": type(value).__name__, **({"length": len(value)} if isinstance(value, str) else {})}


class SetupAuth:
    """Local factory-setup handshake; never authenticates to TP-Link cloud."""
    # Public factory credential from python-kasa's TAPOCAMERA_LV3 profile.
    password_hash = sha(base64.b64decode("VFBMMDc1NTI2NDYwNjAz").decode())

    def __init__(self, password_hash=None):
        if password_hash is not None:
            self.password_hash = password_hash
        self.pending = {}
        self.sessions = {}
        self.lock = threading.RLock()

    def login(self, params, peer):
        with self.lock:
            now = time.monotonic()
            self.pending = {k: v for k, v in self.pending.items() if v[1] > now}
            self.sessions = {k: v for k, v in self.sessions.items() if v["expires"] > now}
            nonce = params.get("cnonce", "")
            if "digest_passwd" in params and "cnonce" not in params:
                # TD21 sends the proof without repeating cnonce. Match only this peer's pending proofs.
                supplied = params.get("digest_passwd")
                if not isinstance(supplied, str):
                    return {"error_code": -40413}
                matches = [client_nonce for (address, client_nonce), (server_nonce, _) in self.pending.items()
                           if address == peer and hmac.compare_digest(supplied,
                               sha(self.password_hash + client_nonce + server_nonce) + client_nonce + server_nonce)]
                if len(matches) != 1:
                    return {"error_code": -40413}
                nonce = matches[0]
            if params.get("username") != "admin" or not isinstance(nonce, str) or not 1 <= len(nonce) <= 64:
                return {"error_code": -40401}
            if "digest_passwd" not in params:
                if len(self.pending) >= 128:
                    return {"error_code": -40401}
                server_nonce = os.urandom(8).hex().upper()
                self.pending[(peer, nonce)] = (server_nonce, now + 60)
                confirm = sha(nonce + self.password_hash + server_nonce)
                return {"error_code": -40413, "result": {"data": {
                    "code": -40413, "encrypt_type": ["3"], "key": "",
                    "nonce": server_nonce, "device_confirm": confirm + server_nonce + nonce}}}
            item = self.pending.pop((peer, nonce), None)
            if item is None:
                return {"error_code": -40413}
            server_nonce = item[0]
            digest = sha(self.password_hash + nonce + server_nonce) + nonce + server_nonce
            supplied = params.get("digest_passwd")
            if not isinstance(supplied, str) or not hmac.compare_digest(supplied, digest):
                LOG.info("LOGIN credential proof rejected peer=%s", peer)
                return {"error_code": -40413}
            if len(self.sessions) >= 128:
                return {"error_code": -40401}
            seed = sha(nonce + self.password_hash + server_nonce)
            token = os.urandom(16).hex().upper()
            self.sessions[token] = {
                "peer": peer, "nonce": nonce, "seq": 100, "expires": now + 300,
                "seen_sequences": set(),
                "password_hash": self.password_hash,
                "key": bytes.fromhex(sha("lsk" + nonce + server_nonce + seed))[:16],
                "iv": bytes.fromhex(sha("ivb" + nonce + server_nonce + seed))[:16]}
            LOG.info("LOGIN handshake established peer=%s", peer)
            return {"error_code": 0, "result": {"stok": token, "user_group": "root", "start_seq": 100}}

    def secure(self, token, peer, raw, headers, dispatch):
        with self.lock:
            session = self.sessions.get(token)
            if not session or session["peer"] != peer or session["expires"] <= time.monotonic():
                LOG.info("SECURE rejected peer=%s reason=session found=%s", peer, bool(session))
                return {"error_code": -40401}
            seq = int(headers.get("Seq", "-1"))
            expected = sha(sha(session["password_hash"] + session["nonce"]) + raw.decode() + str(seq))
            # The app sends parallel requests; retain a bounded replay window, not arrival order.
            minimum = max(100, session["seq"] - 128)
            if not minimum <= seq <= 0x7FFFFFFF or seq in session["seen_sequences"] or not hmac.compare_digest(headers.get("Tapo_tag", ""), expected):
                LOG.info("SECURE rejected peer=%s reason=signature seq=%d expected_seq=%d tag_present=%s headers=%s",
                         peer, seq, session["seq"], bool(headers.get("Tapo_tag")), sorted(headers.keys()))
                return {"error_code": -40401}
            outer = json.loads(raw)
            if outer.get("method") != "securePassthrough":
                return {"error_code": -40210}
            data = base64.b64decode(outer["params"]["request"], validate=True)
            decryptor = Cipher(algorithms.AES(session["key"]), modes.CBC(session["iv"])).decryptor()
            padded = decryptor.update(data) + decryptor.finalize()
            unpad = padding.PKCS7(128).unpadder()
            inner = json.loads(unpad.update(padded) + unpad.finalize())
            # Reserve the sequence before dispatch so parallel requests cannot replay it.
            session["seq"] = max(session["seq"], seq + 1)
            session["seen_sequences"].add(seq)
            session["seen_sequences"] = {s for s in session["seen_sequences"] if s >= session["seq"] - 128}
        response = dispatch(inner)
        padder = padding.PKCS7(128).padder()
        plain = json.dumps(response).encode()
        padded = padder.update(plain) + padder.finalize()
        encryptor = Cipher(algorithms.AES(session["key"]), modes.CBC(session["iv"])).encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        return {"error_code": 0, "seq": seq, "result": {"response": base64.b64encode(encrypted).decode()}}

    def has_session(self, peer):
        with self.lock:
            return any(s["peer"] == peer and s["expires"] > time.monotonic()
                       for s in self.sessions.values())


def setup_language(params, state):
    """Store only the observed setup language setting, in memory."""
    if not isinstance(params, dict):
        return {"error_code": -40209}
    language = params.get("language")
    if not isinstance(language, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,31}", language):
        return {"error_code": -40209}
    state["language"] = language
    return {"error_code": 0, "result": {}}


def packet(body, transaction=b"\0" * 4, *, opcode=1, flags=0x11, reserved=0):
    body = json.dumps(body, separators=(",", ":")).encode()
    header = struct.pack("!BBHHBB4sI", 2, 0, opcode, len(body), flags, reserved,
                         transaction, 0x5A6B7C8D)
    data = bytearray(header + body)
    struct.pack_into("!I", data, 12, zlib.crc32(data))
    return bytes(data)


def decode_probe(data, *, expected_opcode=1):
    if len(data) < 16 or len(data) > 8192:
        raise ValueError("invalid packet size")
    version, _, opcode, length = struct.unpack("!BBHH", data[:6])
    if version != 2 or opcode != expected_opcode or length != len(data) - 16:
        raise ValueError("unsupported header")
    copy = bytearray(data)
    expected = struct.unpack_from("!I", copy, 12)[0]
    struct.pack_into("!I", copy, 12, 0x5A6B7C8D)
    if zlib.crc32(copy) != expected:
        raise ValueError("invalid CRC")
    return json.loads(data[16:]) if data[16:] else {}


def encrypt_discovery(public_key, secret):
    key = serialization.load_pem_public_key(public_key.encode())
    if not isinstance(key, rsa.RSAPublicKey) or not 1024 <= key.key_size <= 4096:
        raise ValueError("unsupported discovery RSA key")
    material = os.urandom(32)
    padder = padding.PKCS7(128).padder()
    plain = json.dumps(secret).encode()
    plain = padder.update(plain) + padder.finalize()
    cipher = Cipher(algorithms.AES(material[:16]), modes.CBC(material[16:])).encryptor()
    encrypted = cipher.update(plain) + cipher.finalize()
    sealed = key.encrypt(material, rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
    return {"sym_schm": "AES", "key": base64.b64encode(sealed).decode(),
            "data": base64.b64encode(encrypted).decode()}


def discovery_result(ip, mac, device_id, model, public_key=None, owner="", configured=False,
                     alias="Tapo Hub"):
    result = {"device_id": device_id, "device_model": model,
              "device_name": alias, "device_type": "SMART.TAPOHUB",
              "factory_default": not configured, "owner": owner, "ip": ip, "mac": mac,
              "is_support_iot_cloud": True, "isResetWiFi": False,
              "hardware_version": "1.0", "firmware_version": "1.0.0 Build 20261108",
              "encrypt_type": ["3"],
              "mgt_encrypt_schm": {"is_support_https": True, "encrypt_type": "AES",
                                   "http_port": 443}, "obd_src": "tplink"}
    if public_key:
        result["encrypt_info"] = encrypt_discovery(public_key, {
            "device_id": device_id, "owner": owner, "http_port": 443,
            "connect_type": "wired", "connect_ssid": "", "sd_status": "offline"})
    return {"error_code": 0, "result": result}


class SetupCommands:
    def __init__(self, auth, cloud, state_file, local_only=False):
        self.auth, self.cloud = auth, cloud
        self.local_only = local_only
        self.path = Path(state_file)
        self.lock = threading.RLock()
        self.state = {"media_encrypt": "off", "timezone": "UTC+00:00", "zone_id": "Etc/UTC"}
        if self.path.exists():
            saved = json.loads(self.path.read_text())
            if not isinstance(saved, dict):
                raise ValueError("invalid saved setup state")
            self.state.update(saved)
            if "password_hash" in saved:
                if not re.fullmatch(r"[A-F0-9]{64}", saved["password_hash"]):
                    raise ValueError("invalid saved password hash")
                auth.password_hash = saved["password_hash"]

    @property
    def associated(self):
        return self.cloud.bound or (self.local_only and self.state.get("binding_mode") == "local"
                                   and bool(self.state.get("owner")))

    def save(self, changes):
        updated = {**self.state, **changes}
        fd, filename = tempfile.mkstemp(dir=self.path.parent, prefix=".setup-")
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(updated, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(filename, self.path)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
        self.state = updated

    def command(self, method, params):
        with self.lock:
            try:
                if not isinstance(params, dict):
                    raise ValueError("invalid params")
                if method == "changeAdminPassword":
                    change = params["user_management"]["change_admin_password"]
                    new = change["passwd"]
                    if change.get("username") != "admin" or change.get("secname") != "root":
                        raise ValueError("unsupported account")
                    if change.get("encrypt_type") != "3" or not isinstance(new, str) or not re.fullmatch(r"[A-Fa-f0-9]{64}", new):
                        raise ValueError("invalid password hash")
                    old = change.get("old_passwd")
                    if not isinstance(old, str) or not hmac.compare_digest(old.upper(), self.auth.password_hash):
                        return {"error_code": -40413}
                    self.save({"password_hash": new.upper()})
                    self.auth.password_hash = new.upper()
                    self.auth.pending.clear()
                    LOG.info("SETUP admin password hash updated")
                elif method == "setDeviceAlias":
                    alias = params["system"]["sys"]["dev_alias"]
                    if not isinstance(alias, str) or not alias.strip() or len(alias.encode()) > 128 or any(ord(c) < 32 for c in alias):
                        raise ValueError("invalid device alias")
                    self.save({"device_alias": alias})
                elif method == "getFirmwareUpdateStatus":
                    # No updater exists in the lab; never report an upgrade in progress.
                    return {"error_code": 0, "result": {"cloud_config": {
                        "upgrade_status": {"state": "normal", "lastUpgradingSuccess": False}}}}
                elif method == "setFirmwareAutoUpgradeConfig":
                    common = params["auto_upgrade"]["common"]
                    if not isinstance(common, dict) or not common or set(common) - {"enabled", "time", "random_range"}:
                        raise ValueError("invalid auto-update preference")
                    previous = self.state.get("auto_upgrade", {"enabled": "off", "time": "03:00", "random_range": 120})
                    preference = {**previous, **common}
                    if preference["enabled"] not in ("on", "off") or not isinstance(preference["time"], str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", preference["time"]):
                        raise ValueError("invalid auto-update preference")
                    if type(preference["random_range"]) is not int or not 0 <= preference["random_range"] <= 1440:
                        raise ValueError("invalid update window")
                    # Save the UI preference only; the lab has no firmware downloader/updater.
                    self.save({"auto_upgrade": preference})
                elif method == "getFirmwareAutoUpgradeConfig":
                    return {"error_code": 0, "result": {"auto_upgrade": {"common": self.state.get(
                        "auto_upgrade", {"enabled": "off", "time": "03:00", "random_range": 120})}}}
                elif method == "getDeviceLoadInfo":
                    # Tapo uses the cam_* fields for cameras; generic fields describe IoT load.
                    # This configured enrollment limit does not prove that video reception works.
                    return {"error_code": 0, "result": {
                        "cam_cur_load_num": 0, "cam_max_load_num": 16, "cam_load_level": "light",
                        "cur_load_num": 0, "max_load_num": 16, "load_level": "light"}}
                elif method in ("getChildDeviceList", "getChildDeviceComponentList"):
                    start = params.get("childControl", {}).get("start_index", 0)
                    if type(start) is not int or start < 0:
                        raise ValueError("invalid list pagination")
                    key = "child_device_list" if method == "getChildDeviceList" else "child_component_list"
                    # Actual paired registry is empty; do not invent camera IDs or pairings.
                    return {"error_code": 0, "result": {key: [], "start_index": 0, "sum": 0}}
                elif method == "getSupportChildDeviceCategory":
                    # The implemented discovery path covers IP cameras; enrollment is a separate step.
                    return {"error_code": 0, "result": {"device_category_list": [{"category": "ipcamera"}]}}
                elif method == "setMediaEncrypt":
                    value = params["cet"]["media_encrypt"]["enabled"]
                    if value not in ("on", "off"):
                        raise ValueError("invalid media setting")
                    self.save({"media_encrypt": value})
                elif method == "setTimezone":
                    basic = params["system"]["basic"]
                    zone, offset = basic["zone_id"], basic["timezone"]
                    if not isinstance(zone, str) or len(zone) > 64 or not isinstance(offset, str) or not re.fullmatch(r"UTC[+-](?:0[0-9]|1[0-4]):[0-5][0-9]", offset):
                        raise ValueError("invalid timezone")
                    ZoneInfo(zone)
                    self.save({"timezone": offset, "zone_id": zone})
                elif method == "bindToCloud":
                    account = params["cloud_config"]["bind"]
                    username, password = account["username"], account["password"]
                    if not isinstance(username, str) or not 3 <= len(username) <= 254 or "@" not in username or not isinstance(password, str) or not 1 <= len(password) <= 4096:
                        raise ValueError("invalid binding account")
                    owner = hashlib.md5(username.encode()).hexdigest().upper()
                    if self.state.get("owner") and self.state["owner"] != owner:
                        return {"error_code": -40401}
                    if self.local_only:
                        # Experimental local account association, not TP-Link cloud registration.
                        self.save({"owner": owner, "binding_mode": "local"})
                        LOG.info("SETUP local account association stored; no cloud request sent")
                    else:
                        if not self.cloud.bind(username, password):
                            return {"error_code": -40101}
                        self.save({"owner": owner, "binding_mode": "cloud"})
                elif method == "getBindStatus":
                    return {"error_code": 0, "result": {"cloud_status": {"bind": {
                        "status": "bound" if self.associated else "unbound",
                        "error_code": 0 if self.associated else -40101}}}}
                elif method == "getCloudConfig":
                    return {"error_code": 0, "result": {"cloud_config": {"device_status": {
                        "status": "connected" if self.cloud.bound else "disconnected"}}}}
                elif method == "getMediaEncrypt":
                    return {"error_code": 0, "result": {"cet": {"media_encrypt": {"enabled": self.state["media_encrypt"]}}}}
                elif method == "getTimezone":
                    return {"error_code": 0, "result": {"system": {"basic": {
                        "timezone": self.state["timezone"], "zone_id": self.state["zone_id"]}}}}
                else:
                    return {"error_code": -40210}
                LOG.info("SETUP command=%s result=0", method)
                return {"error_code": 0, "result": {}}
            except (ValueError, TypeError, KeyError, AttributeError, ZoneInfoNotFoundError):
                # Log keys only, including for credentials with an unexpected schema.
                LOG.info("SETUP command=%s invalid_schema fields=%s", method,
                         sorted(params) if isinstance(params, dict) else [])
                return {"error_code": -40209}
            except OSError:
                LOG.info("SETUP command=%s state_save_failed", method)
                return {"error_code": -40101}


class Diagnostics(BaseHTTPRequestHandler):
    def dispatch(self, request):
        method = request.get("method", "unknown")
        LOG.info("AUTHENTICATED peer=%s method=%s fields=%s", self.client_address[0],
                 str(method)[:80], sorted(str(k)[:80] for k in request))
        if method == "multipleRequest":
            requests = request.get("params", {}).get("requests", [])
            if not isinstance(requests, list) or len(requests) > 32:
                return {"error_code": -40210}
            responses = []
            bind_failed = False
            for item in requests:
                if not isinstance(item, dict):
                    return {"error_code": -40209}
                # A failed registration must not switch away from setup credentials.
                if bind_failed and item.get("method") == "changeAdminPassword":
                    response = {"error_code": -40210}
                else:
                    response = self.dispatch(item)
                if item.get("method") == "bindToCloud" and response["error_code"] != 0:
                    bind_failed = True
                responses.append({**response, "method": item.get("method")})
            return {"error_code": 0, "result": {"responses": responses}}
        if method == "getDeviceInfo":
            self.server.device_info["bind_status"] = bool(self.server.setup.associated)
            self.server.device_info["status"] = "configured" if self.server.setup.state.get("owner") else "unconfigured"
            self.server.device_info["device_alias"] = self.server.setup.state.get("device_alias", "Tapo Hub")
            self.server.device_info["child_num"] = 0
            return {"error_code": 0, "result": {"device_info": {"basic_info": self.server.device_info}}}
        if method == "getAppComponentList":
            components = {"system": 4, "account": 1, "quickSetup": 1, "firmware": 2,
                          "childControl": 1, "deviceLoad": 1, "generalCameraManage": 1, "hardDisk": 1,
                          "hubRecord": 1, "playback": 6}
            faces = getattr(getattr(self, "server", None), "faces", None)
            if faces is not None and faces.client.ready():
                components["faceDetection"] = 1
            return {"error_code": 0, "result": {"app_component": {"app_component_list": [
                {"name": k, "version": v} for k, v in components.items()]}}}
        if method in FACE_METHODS:
            faces = getattr(getattr(self, "server", None), "faces", None)
            if faces is None:
                return {"error_code": -40210}
            response = faces.command(method, request.get("params", {}))
            LOG.info("FACE API method=%s result=%d schema=%s", method, response["error_code"],
                     json.dumps(protocol_schema(request.get("params", {})), separators=(",", ":")))
            return response
        if method in PLAYBACK_METHODS:
            try:
                with activity():
                    response = self.server.playback.command(method, request.get("params", {}))
            except (OSError, ValueError):
                response = {"error_code": -40101}
            LOG.info("PLAYBACK query method=%s result=%d schema=%s", method, response["error_code"],
                     json.dumps(protocol_schema(request.get("params", {})), separators=(",", ":")))
            return response
        if method == "getUserID":
            return {"error_code": 0, "result": {"user_id": 1}}
        if method == "getScaleList":
            return {"error_code": 0, "result": {"playback": {"scale_capability": []}}}
        if method == "getCircularRecordingConfig":
            enabled = getattr(self.server, "retention_enabled", False) if hasattr(self, "server") else False
            return {"error_code": 0, "result": {"harddisk_manage": {"harddisk": {"loop": "on" if enabled else "off"}}}}
        if method == "getClockStatus":
            return {"error_code": 0, "result": {"system": {"clock_status": {
                "seconds_from_1970": int(time.time()), "local_time": datetime.now(
                    ZoneInfo(self.server.setup.state.get("zone_id", "Etc/UTC"))).strftime("%Y-%m-%d %H:%M:%S"),
                "zone_id": self.server.setup.state.get("zone_id", "Etc/UTC")}}}}
        if method == "getDstRule":
            try:
                status = dst_status(self.server.setup.state.get("zone_id", "Etc/UTC"))
            except (OSError, ValueError, IndexError):
                LOG.info("PLAYBACK clock DST metadata unavailable")
                return {"error_code": -40101}
            return {"error_code": 0, "result": {"system": {"dst": status}}}
        if method == "setLanguage":
            return setup_language(request.get("params"), self.server.setup_state)
        if method in ("getHardDiskStatus", "getSdCardStatus"):
            response = storage_status_command(request.get("params", {}))
            LOG.info("STORAGE API method=%s result=%d", method, response["error_code"])
            return response
        if method in ("startScanGeneralDevice", "stopScanGeneralDevice", "getScanGeneralDeviceList",
                      "getGeneralDeviceList"):
            params = request.get("params", {})
            response = camera_discovery_command(method, params, self.server.cameras,
                                                scan=getattr(self.server, "discovery_scan", None),
                                                native=getattr(self.server, "native_storage", None))
            section = params.get("general_camera_manage") if isinstance(params, dict) else None
            LOG.info("CAMERA API method=%s result=%d param_fields=%s section_fields=%s", method,
                     response["error_code"], sorted(params) if isinstance(params, dict) else [],
                     sorted(section) if isinstance(section, dict) else [])
            return response
        if method == "getConnectionType":
            return {"error_code": 0, "result": {"link_type": "ethernet"}}
        if method == "syncHubRequest":
            return self.server.native_storage.sync(request.get("params", {}), self.client_address[0])
        if method in ("storageHubRequest", "backupWifiRequest"):
            if method == "storageHubRequest":
                return self.server.native_storage.command(request.get("params", {}), self.client_address[0])
            LOG.info("CAMERA NATIVE method=%s peer=%s schema=%s", method, self.client_address[0],
                     json.dumps(protocol_schema(request.get("params", {})), separators=(",", ":")))
            return {"error_code": -40210}
        if method in ("bindToCloud", "changeAdminPassword", "setMediaEncrypt", "setTimezone",
                      "setDeviceAlias", "getFirmwareUpdateStatus",
                      "setFirmwareAutoUpgradeConfig", "getFirmwareAutoUpgradeConfig", "getDeviceLoadInfo",
                      "getChildDeviceList", "getChildDeviceComponentList",
                      "getSupportChildDeviceCategory",
                      "getBindStatus", "getCloudConfig", "getMediaEncrypt", "getTimezone"):
            return self.server.setup.command(method, request.get("params", {}))
        # Unknown setup commands must not be acknowledged as successful writes.
        cameras = getattr(self.server, "cameras", None) if hasattr(self, "server") else None
        if cameras is not None:
            with cameras.lock:
                camera_peer = any(record.get("last_ip") == self.client_address[0] for record in cameras.devices.values())
            if camera_peer:
                LOG.info("CAMERA UNSUPPORTED method=%s schema=%s", str(method)[:80],
                         json.dumps(protocol_schema(request.get("params", {})), separators=(",", ":")))
        return {"error_code": -40210}

    def native_stream_ready(self):
        self.native_response_started = True
        self.protocol_version = 'HTTP/1.1'
        self.send_response_only(200)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        self.wfile.flush()
        LOG.info('UPLOAD native stream admission reply sent; recording_not_yet_validated')

    def do_POST(self):
        if self.path.split("?", 1)[0] == "/stream":
            serve_playback(self)
            return
        if self.path in ("/stream/alarm_snapshot", "/stream/alarm_streaming"):
            self.native_response_started = False
            try:
                result = self.server.native_event_capture.receive(self)
                LOG.info("CAMERA EVENT native media validated and saved endpoint=%s bytes=%d",
                         result["endpoint"], result["bytes"])
            except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
                LOG.info("CAMERA EVENT native upload rejected endpoint=%s reason=%s headers=%s", self.path,
                         str(error) if type(error) is ValueError else type(error).__name__, sorted(self.headers.keys()))
                self.close_connection = True
                if not self.native_response_started:
                    self.send_error(503, "Native event could not be validated")
                return
            if self.native_response_started:
                self.connection.settimeout(15)
                self.close_connection = False
                return
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            limit = 65536
            if self.path.startswith("/stok=") and self.path.endswith("/ds"):
                token = self.path[len("/stok="):-len("/ds")]
                with self.server.auth.lock:
                    session = self.server.auth.sessions.get(token)
                    if (session and session["peer"] == self.client_address[0]
                            and session["expires"] > time.monotonic()):
                        # Enrollment supports 1.4 MB of JPEG base64 plus encrypted-envelope overhead.
                        limit = 2 * 1024 * 1024
            if not 0 <= length <= limit:
                LOG.info("HTTPS body rejected bytes=%d limit=%d", length, limit)
                self.close_connection = True
                self.send_error(413)
                return
            raw = self.rfile.read(length)
            request = json.loads(raw)
            method = request.get("method", "unknown")
            # Only method names are logged; no credentials, request bodies or tokens.
            LOG.info("HTTPS peer=%s method=%s bytes=%d", self.client_address[0],
                     str(method)[:80], length)
            response = {"error_code": -40210}
            token_route = self.path.startswith("/stok=") and self.path.endswith("/ds")
            # TD21 restarts its nonce handshake on its old session URL.
            if method == "login" and (self.path == "/" or token_route):
                params = request.get("params", {})
                LOG.info("LOGIN schema fields=%s phase=%s", sorted(str(k)[:80] for k in params),
                         "proof" if "digest_passwd" in params else "challenge")
                response = self.server.auth.login(params, self.client_address[0])
            elif token_route:
                token = self.path[len("/stok="):-len("/ds")]
                response = self.server.auth.secure(token, self.client_address[0], raw,
                                                   self.headers, self.dispatch)
            elif self.path == "/" and method == "setLanguage" and self.server.auth.has_session(self.client_address[0]):
                params = request.get("params")
                LOG.info("SETUP setLanguage param_fields=%s", sorted(params) if isinstance(params, dict) else [])
                response = setup_language(params, self.server.setup_state)
                LOG.info("SETUP setLanguage result=%d", response["error_code"])
            else:
                LOG.info("HTTPS unsupported route peer=%s token_route=%s query=%s trailing_slash=%s",
                         self.client_address[0], self.path.startswith("/stok="),
                         "?" in self.path, self.path.endswith("/"))
            body = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ValueError, TypeError, AttributeError, KeyError):
            LOG.info("HTTPS malformed request peer=%s", self.client_address[0])
            self.send_error(400)

    def log_message(self, *_):
        pass


class NativeMedia(Diagnostics):
    def do_POST(self):
        if self.path not in ("/stream/alarm_snapshot", "/stream/alarm_streaming"):
            self.send_error(404)
            return
        super().do_POST()


def serve(args):
    with open("/sys/class/net/eth0/address") as stream:
        mac = stream.read().strip().upper().replace(":", "-")
    # Device-cloud IDs in the reference protocol are 20 bytes, unlike discovery IDs.
    device_id = hashlib.sha1(("tapo-hub-lab:" + mac).encode()).hexdigest().upper()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.cert, args.key)
    http = TLSHTTPServer(("0.0.0.0", 443), Diagnostics, tls)
    http.auth = SetupAuth()
    http.setup_state = {}
    http.device_info = {"device_type": "SMART.TAPOHUB", "device_model": args.model,
                        "device_alias": "Tapo Hub", "dev_id": device_id,
                        "mac": mac, "ipaddr": args.ip, "hw_version": "1.0", "sw_version": "1.0.0 Build 20261108",
                        "device_info": args.model + " 1.0", "hw_id": "", "oem_id": ""}
    http.cloud = CloudClient(http.device_info, args.cloud_ca, enabled=args.enable_cloud_registration)
    http.setup = SetupCommands(http.auth, http.cloud, args.state_file, local_only=args.local_only_setup)
    http.cameras = CameraRegistry("/var/lib/tapo-hub/cameras.json",
                                  "/etc/tapo-hub/cameras.json")
    http.native_storage = NativeStorage("/var/lib/tapo-hub/enrolled.json", http.cameras,
                                        http.setup, http.device_info)
    http.native_event_capture = NativeEventCapture(http.native_storage)
    http.playback = RecordingPlayback(http.native_storage)
    http.faces = None
    if os.environ.get("TAPO_FACE_RECOGNITION") == "1":
        try:
            from face_database import FaceDatabase
            from camera_media import STORE
            with activity():
                database = FaceDatabase(STORE / "faces" / "faces.duckdb")
            http.faces = FaceAPI(database, FaceClient(), http.playback)
            LOG.info("FACE DuckDB backend ready counts=%s", json.dumps(database.counters(), separators=(",", ":")))
            threading.Thread(target=http.faces.watch, daemon=True).start()
        except Exception as error:
            LOG.info("FACE initialization deferred; recording remains active reason=%s", type(error).__name__)
    http.media_auth = MediaAuth()
    threading.Thread(target=watch_retention, daemon=True).start()
    http.retention_enabled = True
    threading.Thread(target=watch_observation, daemon=True).start()
    start_camera_discovery(args.ip, http.device_info, http.setup, http.cameras, packet, decode_probe)
    http.discovery_scan = LocalScan(http.cameras, args.ip, http.setup)
    threading.Thread(target=watch_cameras, args=(http.cameras, packet, decode_probe), daemon=True).start()
    if args.local_only_setup:
        LOG.info("MODE local-only setup emulation; TP-Link cloud registration disabled")
    threading.Thread(target=http.serve_forever, daemon=True).start()
    media = TLSHTTPServer(("0.0.0.0", 21443), NativeMedia, tls)
    media.native_event_capture = http.native_event_capture
    threading.Thread(target=media.serve_forever, daemon=True).start()
    playback = BoundedHTTPServer(("0.0.0.0", 8800), PlaybackMedia)
    playback.setup, playback.playback, playback.media_auth = http.setup, http.playback, http.media_auth
    playback.faces = http.faces
    threading.Thread(target=playback.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 20002))
    LOG.info("READY model=%s ip=%s mac=%s discovery=20002 HTTPS=443 media=21443; enrollment=PERSISTENT_NATIVE recording=UNVERIFIED",
             args.model, args.ip, mac)
    while True:
        data, peer = udp.recvfrom(8193)
        try:
            from camera_registry import LAN
            import ipaddress
            if ipaddress.IPv4Address(peer[0]) not in LAN:
                continue
            request = decode_probe(data)
            public_key = request.get("params", {}).get("rsa_key")
            response = discovery_result(args.ip, mac, device_id, args.model, public_key,
                owner=http.setup.state.get("owner", ""),
                configured=http.auth.password_hash != SetupAuth.password_hash,
                alias=http.setup.state.get("device_alias", "Tapo Hub"))
            udp.sendto(packet(response, data[8:12]), peer)
            LOG.info("DISCOVERY peer=%s:%s rsa=%s replied_model=%s", *peer,
                     bool(public_key), args.model)
        except (ValueError, TypeError, AttributeError, KeyError, struct.error):
            LOG.info("IGNORED malformed/unsupported discovery peer=%s bytes=%d", peer[0], len(data))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--model", choices=["H500", "H200"], default="H500")
    parser.add_argument("--cert", default="/etc/tapo-hub/cert.pem")
    parser.add_argument("--key", default="/etc/tapo-hub/key.pem")
    parser.add_argument("--cloud-ca", default="/opt/tapo-hub/app/tplink-cloud-ca.pem")
    parser.add_argument("--state-file", default="/var/lib/tapo-hub/state.json")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local-only-setup", action="store_true",
                      help="Experimentally associate the app account locally, without cloud registration")
    mode.add_argument("--enable-cloud-registration", action="store_true",
                        help="Send this lab's identity and app-provided binding account to TP-Link")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    serve(parser.parse_args())
