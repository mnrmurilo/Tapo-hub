"""MAC-keyed inventory and local discovery, separate from camera enrollment."""
import argparse
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

LOG = logging.getLogger("tapo-hub-lab")
from settings import LAN


def camera_supported(record):
    model = record.get("model", record.get("device_model"))
    hardware = record.get("hardware_version", "")
    return model == "TD21" or (isinstance(hardware, str)
        and (model, hardware.split(".")[0]) in (("C400", "2"), ("TC70", "5")))


def normalize_mac(value):
    if not isinstance(value, str):
        raise ValueError("MAC must be a string")
    value = value.replace("-", "").replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{12}", value) or int(value[:2], 16) & 1 or value == "0" * 12:
        raise ValueError("Invalid unicast MAC")
    return ":".join(value[i:i+2] for i in range(0, 12, 2))


class CameraRegistry:
    def __init__(self, path, seed):
        self.path = Path(path)
        self.lock = threading.Lock()
        configured = json.loads(Path(seed).read_text())
        data = json.loads(self.path.read_text()) if self.path.exists() else configured
        if not isinstance(data, dict) or not isinstance(data.get("devices"), dict) or not isinstance(data.get("pending"), list):
            raise ValueError("Invalid camera registry")
        allowed = {normalize_mac(mac) for mac in configured['devices']}
        allowed.update(normalize_mac(mac) for mac, record in data['devices'].items()
                       if any(record['model'] == item['model'] and record['seed_ip'] == item['seed_ip']
                              for item in configured['pending']))
        self.devices = {normalize_mac(mac): record for mac, record in data["devices"].items()
                        if normalize_mac(mac) in allowed}
        for mac, record in configured["devices"].items():
            mac = normalize_mac(mac)
            if mac in self.devices and self.devices[mac]["model"] != record["model"]:
                raise ValueError("Configured MAC already belongs to another model")
            if mac in self.devices:
                self.devices[mac]['seed_ip'] = record['seed_ip']
                self.devices[mac]['continuous'] = record.get('continuous', False)
                if self.devices[mac].get('last_ip') and ipaddress.IPv4Address(self.devices[mac]['last_ip']) not in LAN:
                    self.devices[mac].update(last_ip=None, last_seen=0)
            else:
                self.devices[mac] = record
        self.pending = [item for item in configured["pending"] if not any(
            item["model"] == record["model"] and item["seed_ip"] == record["seed_ip"]
            for record in self.devices.values())]
        for record in [*self.devices.values(), *self.pending]:
            if not isinstance(record, dict) or record.get("model") not in ("TD21", "C400", "TC70"):
                raise ValueError("Invalid camera model")
            if ipaddress.IPv4Address(record["seed_ip"]) not in LAN:
                raise ValueError("Camera hint is outside this LAN")
            if record.get("last_ip") is not None and ipaddress.IPv4Address(record["last_ip"]) not in LAN:
                raise ValueError("Saved camera address is outside this LAN")
        self.save()

    def save(self):
        fd, filename = tempfile.mkstemp(dir=self.path.parent, prefix=".cameras-")
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump({"devices": self.devices, "pending": self.pending}, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(filename, self.path)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    def observe(self, result, peer_ip, now=None, *, hub_scan=False):
        try:
            if ipaddress.IPv4Address(peer_ip) not in LAN:
                return False
            mac = normalize_mac(result.get("mac"))
            model = result.get("device_model", "").split("(")[0].strip().upper()
            # D210 and TD21 share the documented product/firmware family.
            model = {"D210": "TD21"}.get(model, model)
        except (ValueError, TypeError, AttributeError):
            return False
        with self.lock:
            record = self.devices.get(mac)
            if record is None:
                record = next((item for item in self.pending
                               if item["seed_ip"] == peer_ip and item["model"] == model), None)
                if record is None:
                    return False
            if model != record["model"]:
                return False
            if mac not in self.devices:
                self.pending.remove(record)
                self.devices[mac] = record
                LOG.info("CAMERA inventory MAC identified model=%s", model)
            # A reused address cannot remain attached to a different configured camera.
            for other_mac, other in self.devices.items():
                if other_mac != mac and other.get("last_ip") == peer_ip:
                    other["last_ip"] = None
                    other["last_seen"] = 0
            record["last_ip"] = peer_ip
            record["last_seen"] = time.time() if now is None else now
            if hub_scan:
                record["hub_discovery"] = {"last_seen": record["last_seen"], "ipaddr": peer_ip,
                    "device_type": str(result.get("device_type", ""))[:64],
                    "alias": str(result.get("device_name", model))[:128],
                    "network_mode": str(result.get("network_mode", ""))[:32]}
            for key in ("firmware_version", "hardware_version"):
                value = result.get(key)
                if isinstance(value, str) and len(value) <= 160:
                    record[key] = value
            self.save()
            LOG.info("CAMERA local discovery model=%s ip=%s", model, peer_ip)
            return True

    def resolve(self, mac, now=None):
        with self.lock:
            record = self.devices.get(normalize_mac(mac))
            age = (time.time() if now is None else now) - record.get("last_seen", 0) if record else 181
            return record.get("last_ip") if record and 0 <= age <= 180 else None

    def refresh_neighbors(self, arp_text, now=None):
        """Use complete local ARP mappings; these are address hints, not authentication."""
        neighbors = {}
        for line in arp_text.splitlines()[1:]:
            fields = line.split()
            try:
                if len(fields) < 6 or not int(fields[2], 16) & 2 or ipaddress.IPv4Address(fields[0]) not in LAN:
                    continue
                neighbors[fields[0]] = normalize_mac(fields[3])
            except (ValueError, TypeError):
                continue
        with self.lock:
            for pending in list(self.pending):
                mac = neighbors.get(pending["seed_ip"])
                if mac and mac not in self.devices:
                    self.devices[mac] = pending
                    self.pending.remove(pending)
                    LOG.info("CAMERA inventory MAC identified from supplied IP model=%s", pending["model"])
            for mac, record in self.devices.items():
                addresses = [ip for ip, observed_mac in neighbors.items() if mac == observed_mac]
                # Don't choose between multiple cached addresses for the same MAC.
                if len(addresses) != 1:
                    continue
                address = addresses[0]
                for other_mac, other in self.devices.items():
                    if other_mac != mac and other.get("last_ip") == address:
                        other["last_ip"] = None
                        other["last_seen"] = 0
                record.update(last_ip=address, last_seen=time.time() if now is None else now,
                              address_source="arp")
            self.save()


def scan_once(registry, encode_packet, decode_packet):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    probe = encode_packet({"params": {"rsa_key": public}}, os.urandom(4))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(0.3)
        stream.bind(("0.0.0.0", 0))
        with registry.lock:
            records = [r for r in [*registry.devices.values(), *registry.pending] if camera_supported(r)]
            targets = {address for record in records for address in
                       (record["seed_ip"], record.get("last_ip")) if address}
        for target in targets:
            stream.sendto(probe, (target, 20002))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                raw, peer = stream.recvfrom(8193)
                reply = decode_packet(raw)
                if peer[0] in targets and reply.get("error_code") == 0 and isinstance(reply.get("result"), dict):
                    registry.observe(reply["result"], peer[0])
            except socket.timeout:
                continue
            except (ValueError, TypeError, AttributeError):
                continue


def watch_cameras(registry, encode_packet, decode_packet):
    while True:
        try:
            scan_once(registry, encode_packet, decode_packet)
        except (OSError, ValueError):
            LOG.info("CAMERA discovery unavailable; retaining MAC bindings without assuming an IP")
        try:
            registry.refresh_neighbors(Path("/proc/net/arp").read_text())
        except (OSError, ValueError):
            LOG.info("CAMERA neighbor cache unavailable")
        time.sleep(60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true", required=True)
    args = parser.parse_args()
    print(Path("/var/lib/tapo-hub/cameras.json").read_text())
