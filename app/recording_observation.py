"""A bounded 24-hour TD21 observation using local metadata only; never wakes a camera."""
import json
import logging
import os
from pathlib import Path
import tempfile
import time

from camera_media import STORE
from recording_retention import activity, check_store, free_bytes

STATE = Path("/var/lib/tapo-hub/observation.json")
LOG = logging.getLogger("tapo-hub-lab")


def sample(now=None):
    now = time.time() if now is None else now
    state = json.loads(STATE.read_text()) if STATE.exists() else None
    if state is not None and state.get("complete"):
        return state
    check_store()
    videos = set()
    for index in (STORE / "events").glob("event-*.mp4.json"):
        if index.is_symlink() or index.stat().st_size > 2_000_000:
            continue
        try:
            details = json.loads(index.read_text())
            media = Path(str(index)[:-5])
            if (details.get("validated_recording") is True and details.get("format_version") == 1
                    and media.is_file() and not media.is_symlink() and media.stat().st_size == details["bytes"]):
                videos.add(index.name)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    failures = {path.name for path in (STORE / "failed-uploads").glob("*.wire.json")}
    failures.update(path.name for path in (STORE / "failed-uploads" / "td21").glob("*.wire.json"))
    if state is None:
        state = {"started_at": now, "complete": False, "baseline_videos": sorted(videos),
                 "baseline_failures": sorted(failures), "new_videos": [], "new_failures": [], "samples": []}
    new_videos = set(state["new_videos"]) | (videos - set(state["baseline_videos"]))
    new_failures = set(state["new_failures"]) | (failures - set(state["baseline_failures"]))
    enrolled = json.loads((STATE.parent / "enrolled.json").read_text())
    linked = any(item.get("device_model") == "TD21" and item.get("hub_storage_enabled")
                 and item.get("recording_mode") == "persistent_native" for item in enrolled.values())
    state["new_videos"], state["new_failures"] = sorted(new_videos)[:5000], sorted(new_failures)[:5000]
    state["samples"] = (state["samples"] + [{"time": now, "linked": linked, "free_bytes": free_bytes(),
        "completed_videos": len(videos), "new_completed_videos": len(new_videos),
        "new_retained_failed_events": len(new_failures)}])[-300:]
    state["complete"] = now - state["started_at"] >= 86_400
    fd, path = tempfile.mkstemp(dir=STATE.parent, prefix=".observation-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
        os.replace(path, STATE)
    finally:
        Path(path).unlink(missing_ok=True)
    return state


def watch():
    while True:
        try:
            with activity():
                state = sample()
            if state["complete"]:
                LOG.info("OBSERVATION 24-hour metadata collection complete")
                return
        except (OSError, ValueError, KeyError, TypeError) as error:
            LOG.info("OBSERVATION sample failed reason=%s", type(error).__name__)
        time.sleep(300)
