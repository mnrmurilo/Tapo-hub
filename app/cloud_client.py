"""Experimental legacy Tapo device-cloud client, using only this lab's identity.

Framing/helloCloud reference: Imre Rad's DeepSec 2023 device protocol research.
No device impersonation, identity cloning, or certificate-verification bypass.
Compatibility with H500 cloud registration is not established.
"""
import json
import logging
import socket
import ssl
import struct
import threading
import time

LOG = logging.getLogger("tapo-hub-lab")
HOST = "n-devs.tplinkcloud.com"


def encode(message):
    body = json.dumps(message, separators=(",", ":")).encode()
    if not 0 < len(body) <= 65535:
        raise ValueError("invalid cloud frame size")
    return b"\xa1\xb2" + struct.pack("!H", len(body)) + body


def receive(stream):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            chunk = stream.recv(size - len(data))
            if not chunk:
                raise ConnectionError("cloud connection closed")
            data.extend(chunk)
        return bytes(data)
    header = exact(4)
    if header[:2] != b"\xa1\xb2":
        raise ValueError("invalid cloud frame header")
    length = struct.unpack("!H", header[2:])[0]
    if not length:
        raise ValueError("empty cloud frame")
    response = json.loads(exact(length))
    if not isinstance(response, dict):
        raise ValueError("invalid cloud response")
    return response


class CloudClient:
    def __init__(self, info, ca_file, connector=None, enabled=False):
        self.info = info
        self.ca_file = ca_file
        self.connector = connector or self.connect
        self.enabled = enabled
        self.stream = None
        self.counter = 0
        self.lock = threading.Lock()
        self.bound = False
        self.bound_username = None
        self.last_stage = "not_attempted"
        self.last_code = None
        self.stop = threading.Event()
        self.last_attempt = 0

    def connect(self):
        if not self.enabled:
            raise PermissionError("cloud registration disabled")
        context = ssl.create_default_context(cafile=self.ca_file)
        raw = socket.create_connection((HOST, 443), timeout=4)
        try:
            stream = context.wrap_socket(raw, server_hostname=HOST)
            stream.settimeout(4)
            return stream
        except Exception:
            raw.close()
            raise

    def call(self, method, params):
        self.counter += 1
        request_id = self.counter
        self.stream.sendall(encode({"id": request_id, "method": method, "params": params}))
        # Bound the number of unsolicited messages consumed while awaiting a reply.
        for _ in range(16):
            reply = receive(self.stream)
            if reply.get("id") == request_id and "method" not in reply:
                if type(reply.get("error_code")) is not int:
                    raise ValueError("cloud reply omitted numeric status")
                return reply
            # Relay/control is not implemented; reject rather than claim success.
            if "method" in reply and type(reply.get("id")) is int:
                self.stream.sendall(encode({"id": reply["id"], "error_code": -40210}))
        raise ValueError("no matching cloud response")

    def hello(self):
        if not self.enabled:
            self.last_stage = "disabled"
            return False
        self.last_stage = "helloCloud"
        info = self.info
        self.stream = self.connector()
        reply = self.call("helloCloud", {
            "deviceId": info["dev_id"], "deviceMac": info["mac"].replace("-", ""),
            "hwId": info.get("hw_id", ""), "tcspVer": "1.2", "cloudUserName": "",
            "deviceName": info["device_model"], "deviceModel": info["device_model"],
            "deviceHwVer": info["hw_version"], "fwVer": info["sw_version"],
            "fwId": info.get("fw_id", ""), "oemId": info.get("oem_id", ""),
            "alias": "Tapo Hub"})
        self.last_code = reply["error_code"]
        LOG.info("CLOUD stage=helloCloud code=%d", self.last_code)
        result = reply.get("result", {})
        if self.last_code != 0 or not isinstance(result, dict) or result.get("illegalType") != 0:
            self.last_stage = "hello_rejected"
            self.close()
            return False
        return True

    def bind(self, username, password):
        with self.lock:
            if not self.enabled:
                self.last_stage = "disabled"
                LOG.info("CLOUD registration disabled; no data sent")
                return False
            if self.bound:
                return username == self.bound_username
            if time.monotonic() - self.last_attempt < 60:
                return False
            self.last_attempt = time.monotonic()
            self.bound = False
            try:
                if not self.hello():
                    return False
                self.last_stage = "bindDevice"
                reply = self.call("bindDevice", {"deviceId": self.info["dev_id"],
                    "cloudUserName": username, "cloudPassword": password})
                self.last_code = reply["error_code"]
                LOG.info("CLOUD stage=bindDevice code=%d", self.last_code)
                # Require explicit account confirmation; error_code alone is insufficient.
                self.bound = self.last_code == 0 and bool(reply.get("result", {}).get("accountId"))
                self.last_stage = "bound" if self.bound else "bind_rejected"
                if self.bound:
                    self.bound_username = username
                    threading.Thread(target=self.keepalive, daemon=True).start()
                else:
                    self.close()
                return self.bound
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                LOG.info("CLOUD stage=%s transport_or_protocol_failure", self.last_stage)
                self.last_stage = "transport_or_protocol_failure"
                self.close()
                return False

    def keepalive(self):
        while not self.stop.wait(25):
            with self.lock:
                if not self.bound:
                    return
                try:
                    if self.call("heartBeat", {})["error_code"] != 0:
                        raise ConnectionError("heartbeat rejected")
                except (OSError, ValueError, KeyError, TypeError):
                    self.last_stage = "disconnected"
                    self.bound = False
                    self.close()
                    LOG.info("CLOUD disconnected")
                    return

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None
