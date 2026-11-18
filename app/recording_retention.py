"""Oldest-first retention confined to the dedicated, validated lab recording store."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import stat
import time

from camera_media import STORE
from camera_registry import normalize_mac
from storage_status import disk_info

LOW_FREE = 1_000_000_000
TARGET_FREE = 2_000_000_000
GRACE_SECONDS = 300
LOG = logging.getLogger("tapo-hub-lab")


def free_bytes():
    usage = os.statvfs(STORE)
    return usage.f_bavail * usage.f_frsize


def check_store():
    if STORE.is_symlink() or not os.path.ismount(STORE) or disk_info()["status"] not in ("normal", "full"):
        raise ValueError("Dedicated recording filesystem unavailable")
    events = STORE / "events"
    if events.is_symlink() or (events.exists() and events.stat().st_dev != STORE.stat().st_dev):
        raise ValueError("Unsafe recording directory")


@contextmanager
def activity(*, exclusive=False):
    """A shared lease protects uploads/readers; cleanup takes a brief exclusive lease."""
    check_store()
    fd = os.open(STORE / ".retention.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_dev != STORE.stat().st_dev:
            raise ValueError("Unsafe retention lock")
        fcntl.flock(fd, (fcntl.LOCK_EX | fcntl.LOCK_NB) if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)


def completed_group(stem):
    """Only the publisher's canonical media/index pairs are eligible for removal."""
    if not re.fullmatch(r"event-[0-9a-f]{24}", stem):
        return None
    paths = []
    try:
        for kind in ("mp4", "jpg"):
            media = STORE / "events" / (stem + "." + kind)
            index = media.with_suffix(media.suffix + ".json")
            if not media.exists() and not index.exists() and not media.is_symlink() and not index.is_symlink():
                continue
            for path in (media, index):
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_dev != STORE.stat().st_dev:
                    return None
            if index.stat().st_size > 2_000_000:
                return None
            metadata = json.loads(index.read_text())
            mac = normalize_mac(metadata["camera_mac"])
            event_id = metadata["event_id"]
            if not isinstance(event_id, str) or not re.fullmatch(r"[0-9]{1,20}", event_id):
                return None
            expected = "event-" + hashlib.sha256((mac + ":" + event_id).encode()).hexdigest()[:24]
            if (expected != stem or metadata.get("format_version") != 1 or metadata.get("format") != kind
                    or metadata.get("validated_recording") is not (kind == "mp4")
                    or not 0 < media.stat().st_size == metadata.get("bytes")
                    or not any(track.get("codec_type") == "video" for track in metadata.get("verified_tracks", []))):
                return None
            paths.extend((index, media))
        if not paths:
            return None
        newest = max(path.stat().st_mtime for path in paths)
        return paths, newest
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def cleanup(*, dry_run=False):
    result = {"status": "ready", "deleted_events": 0, "planned_events": 0, "removed_bytes": 0}
    try:
        check_store()
        initial_free = free_bytes()
        result["free_bytes"] = initial_free
        if initial_free >= LOW_FREE:
            return result
        candidates = set()
        for path in (STORE / "events").glob("event-*.json"):
            match = re.fullmatch(r"(event-[0-9a-f]{24})\.(?:mp4|jpg)\.json", path.name)
            if match:
                candidates.add(match[1])
        ordered = []
        for stem in candidates:
            group = completed_group(stem)
            if group is not None:
                ordered.append((group[1], stem))
        for _, stem in sorted(ordered):
            if result["planned_events"] >= 128:
                break
            with activity(exclusive=True):
                check_store()
                available = initial_free + result["removed_bytes"] if dry_run else free_bytes()
                if available >= TARGET_FREE:
                    break
                group = completed_group(stem)
                if group is None or group[1] > time.time() - GRACE_SECONDS:
                    continue
                size = sum(path.stat().st_size for path in group[0])
                if not dry_run:
                    for path in group[0]:
                        path.unlink()
                    result["deleted_events"] += 1
                result["planned_events"] += 1
                result["removed_bytes"] += size
        result["free_bytes"] = free_bytes()
    except BlockingIOError:
        result["status"] = "busy"
    except (OSError, ValueError):
        result["status"] = "unavailable"
    return result


def watch():
    while True:
        result = cleanup()
        if result["deleted_events"] or result["status"] == "unavailable":
            LOG.info("RETENTION %s", json.dumps(result, separators=(",", ":")))
        time.sleep(300)
