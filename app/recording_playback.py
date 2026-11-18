"""Read-only Tapo playback queries over MAC-scoped validated camera recordings."""
from datetime import datetime, timedelta
import calendar
import json
import math
import logging
import os
from pathlib import Path
import re
import threading
import stat
from zoneinfo import ZoneInfo

from camera_media import STORE
from camera_registry import normalize_mac, camera_supported
from storage_status import disk_info

METHODS = {"searchDateWithVideo": "search_year_utility", "searchVideoWithUTC": "search_video_with_utc",
           "searchVideoOfDay": "search_video_utility", "searchDetectionList": "search_detection_list"}
LOG = logging.getLogger("tapo-hub-lab")
DETECTION_ALARMS = {"MD": 2, "PD": 6}


def filter_summary(query):
    """Bounded playback filters only; never log camera IDs, MACs or player IDs."""
    return {key: value for key, value in query.items()
            if key in ("start_date", "end_date", "date", "start_time", "end_time", "start_index", "end_index", "channel")
            and ((type(value) is int and 0 <= value <= 4_102_444_800)
                 or (isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value))
                 or (key == "channel" and value == [0]))}


def integer(value, low=0, high=4_102_444_800):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,10}", str(value)) or not low <= int(value) <= high:
        raise ValueError("Invalid playback integer")
    return int(value)


def calendar_date(value, *, month_end=False):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{8}", value):
        raise ValueError("Invalid playback date")
    year, month, day = int(value[:4]), int(value[4:6]), int(value[6:])
    # iOS uses day 31 as the inclusive end of every month, including February.
    if month_end and 1 <= day <= 31:
        day = min(day, calendar.monthrange(year, month)[1])
    return datetime(year, month, day).date()


class RecordingPlayback:
    def __init__(self, storage):
        self.storage = storage
        self._index_lock = threading.Lock()
        self._indexes = {}

    def camera(self, query):
        # Explicitly selected, previously paired cameras retain read access to saved footage.
        selected = any(query.get(key) for key in ('child_device_mac', 'camera_mac', 'child_device_id'))
        with self.storage.lock:
            cameras = [(mac, dict(record)) for mac, record in self.storage.devices.items()
                       if camera_supported(record) and (selected or record.get("hub_storage_enabled"))]
        for key in ("child_device_mac", "camera_mac"):
            if query.get(key):
                selected = normalize_mac(query[key])
                cameras = [(mac, record) for mac, record in cameras if mac == selected]
        if query.get("child_device_id"):
            cameras = [(mac, record) for mac, record in cameras if record["device_id"] == query["child_device_id"]]
        if len(cameras) != 1:
            raise ValueError("No unique active playback camera")
        mac, record = cameras[0]
        for key in ("child_device_mac", "camera_mac"):
            if query.get(key) and normalize_mac(query[key]) != mac:
                raise ValueError("Wrong playback camera")
        if query.get("child_device_id") and query["child_device_id"] != record["device_id"]:
            raise ValueError("Wrong playback identity")
        for key in ("channel", "channels"):
            if key in query and query[key] not in (0, [0]):
                raise ValueError("Unsupported playback channel")
        return mac

    def recordings(self, query):
        for key in ("channel", "channels"):
            if key in query and query[key] not in (0, [0]):
                raise ValueError("Unsupported playback channel")
        info = getattr(self.storage, 'device_info', {})
        hub = normalize_mac(info['mac']) if info.get('mac') else None
        hub_keys = {key for key in ('camera_mac', 'child_device_mac')
                    if hub and query.get(key) and normalize_mac(query[key]) == hub}
        narrowed = {key: value for key, value in query.items() if key not in hub_keys}
        # The iPhone face player uses bare /stream and selector-free hub queries.
        if not any(narrowed.get(key) for key in ('camera_mac', 'child_device_mac', 'child_device_id')):
            with self.storage.lock:
                allowed = {mac for mac, record in self.storage.devices.items() if camera_supported(record)}
        else:
            allowed = {self.camera(narrowed)}
        if not os.path.ismount(STORE) or disk_info()["status"] not in ("normal", "full"):
            raise ValueError("Recording filesystem unavailable")
        directory = STORE / "events"
        recordings = []
        with self._index_lock:
            retained = {}
            for index in directory.glob("event-*.mp4.json"):
                try:
                    info = index.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 2_000_000:
                        continue
                    signature = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)
                    cached = self._indexes.get(index)
                    if cached is not None and cached[0] == signature:
                        item = cached[1]
                    else:
                        item = json.loads(index.read_text())
                    retained[index] = (signature, item)
                    path = Path(str(index)[:-5])
                    media = path.lstat()
                    if (item.get("camera_mac") not in allowed or item.get("validated_recording") is not True
                            or item.get("format_version") != 1 or not stat.S_ISREG(media.st_mode)
                            or media.st_size != item["bytes"]):
                        continue
                    duration = (float(item["duration"]) if item.get("event_type") == "continuous"
                                else len(item["video_pts"]) / item["rate"])
                    if not math.isfinite(duration) or not 0 < duration <= 125:
                        continue
                    start = integer(item.get("source_time"), 1)
                    recordings.append({"path": path, "start": start, "end": start + math.ceil(duration),
                                       "duration": duration, "file_id": path.stem, "event_type": item.get("event_type", ""),
                                       "camera_mac": item['camera_mac'],
                                       "precise_start": float(item.get("source_time_precise", start))})
                except (OSError, ValueError, TypeError, KeyError, ZeroDivisionError, AttributeError):
                    continue
            self._indexes = retained
        return sorted(recordings, key=lambda row: (row["start"], row["camera_mac"], row["file_id"]))

    def command(self, method, params):
        stage = "schema"
        try:
            section = params["playback"]
            query = section[METHODS[method]]
            if not isinstance(query, dict):
                raise ValueError("Invalid playback query")
            LOG.info("PLAYBACK filters method=%s values=%s", method, json.dumps(filter_summary(query), separators=(",", ":")))
            stage = "camera_or_store"
            rows = self.recordings(query)
            stage = "range"
            zone = ZoneInfo(self.storage.setup.state.get("zone_id", "Etc/UTC"))
            if method == "searchDateWithVideo":
                first = calendar_date(query["start_date"])
                last = calendar_date(query["end_date"], month_end=True)
                if last < first:
                    raise ValueError("Reversed date range")
                dates = set()
                for row in rows:
                    day = datetime.fromtimestamp(row["start"], zone).date()
                    end = datetime.fromtimestamp(row["end"] - 1, zone).date()
                    while day <= end:
                        if first <= day <= last:
                            dates.add(day.strftime("%Y%m%d"))
                        day += timedelta(days=1)
                result = {"search_results": [{"search_results_" + str(i + 1): {"date": day}}
                                              for i, day in enumerate(sorted(dates))]}
            else:
                if method == "searchVideoOfDay":
                    day = datetime.strptime(query["date"], "%Y%m%d").replace(tzinfo=zone)
                    start, end = int(day.timestamp()), int((day + timedelta(days=1)).timestamp()) - 1
                else:
                    start, end = integer(query["start_time"]), integer(query["end_time"])
                if end < start:
                    raise ValueError("Reversed playback range")
                rows = [row for row in rows if row["start"] <= end and row["end"] > start]
                if method == "searchDetectionList":
                    rows = [row for row in rows if row["event_type"] in DETECTION_ALARMS]
                first = integer(query.get("start_index", 0), high=999_999_999)
                last = integer(query.get("end_index", first + 99), first, 999_999_999)
                page = rows[first:min(last + 1, first + 1000)]
                continued = int(first + len(page) < len(rows))
                if method == "searchDetectionList":
                    result = {"snapshot_enable": True, "to_be_continued": continued, "total_num": len(rows),
                              "search_detection_list": [{"start_time": row["start"], "end_time": row["end"],
                                  "alarm_type": DETECTION_ALARMS[row["event_type"]],
                                  "file_id": str(row["start"]), "channelId": 0} for row in page]}
                else:
                    result = {"to_be_continued": continued, "search_video_results": [
                        {"search_video_results_" + str(first + i + 1): {"startTime": row["start"],
                         "endTime": row["end"], "channel": 0,
                         "video_type": "1" if row["event_type"] == "continuous" else "2",
                         "vedio_type": "1" if row["event_type"] == "continuous" else "2"}}
                        for i, row in enumerate(page)]}
            LOG.info("PLAYBACK result method=%s items=%d", method,
                     len(result.get("search_results", result.get("search_video_results", result.get("search_detection_list", [])))))
            return {"error_code": 0, "result": {"playback": result}}
        except (ValueError, TypeError, KeyError, OSError) as error:
            LOG.info("PLAYBACK rejected method=%s stage=%s reason=%s", method, stage, type(error).__name__)
            return {"error_code": -40209}

    def select(self, query):
        start = integer(query["start_time"], 1)
        end = integer(query["end_time"], 1) if "end_time" in query else None
        if end is not None and (end <= start or end - start > 86_400):
            raise ValueError("Invalid stream range")
        # Exact event starts take priority when motion overlaps continuous video.
        rows = sorted(self.recordings(query), key=lambda row: (row["start"] != start,
                      row["event_type"] == "continuous", row["start"]))
        matches = [row for row in rows if row['start'] <= start < row['start'] + row['duration']]
        exact = [row for row in matches if row['start'] == start]
        choices = exact or matches
        if not choices:
            raise ValueError('No completed recording at requested time')
        if len({row['camera_mac'] for row in choices}) != 1:
            raise ValueError('Ambiguous hub recording; select a source camera')
        row = choices[0]
        offset = start - row['start']
        duration = row['duration'] - offset
        return row, offset, min(duration, end-start) if end is not None else duration

    def stream_files(self, query):
        row, offset, duration = self.select(query)
        files = [row]
        if row["event_type"] != "continuous":
            return row, files, offset, duration
        limit = min(120, integer(query["end_time"], 1) - integer(query["start_time"], 1)) if "end_time" in query else 120
        previous = row
        for following in self.recordings(query):
            if following['camera_mac'] != row['camera_mac']:
                continue
            if following["event_type"] != "continuous" or following["precise_start"] <= previous["precise_start"]:
                continue
            if abs(following["precise_start"] - previous["precise_start"] - previous["duration"]) > .2:
                break
            if duration >= limit:
                break
            files.append(following)
            duration += following["duration"]
            previous = following
        return row, files, offset, min(duration, limit)

    def thumbnail(self, query):
        # A recorded image is a point lookup; native clients may send end_time=0.
        row, _, _ = self.select({key: value for key, value in query.items() if key != "end_time"})
        image = row["path"].with_suffix(".jpg")
        index = image.with_suffix(".jpg.json")
        if (not image.is_file() or image.is_symlink() or not index.is_file() or index.is_symlink()
                or not 0 < image.stat().st_size <= 2_000_000 or index.stat().st_size > 2_000_000):
            raise ValueError("No validated recording thumbnail")
        details = json.loads(index.read_text())
        if (details.get("format_version") != 1 or details.get("format") != "jpg"
                or details.get("camera_mac") != row['camera_mac'] or details.get("bytes") != image.stat().st_size):
            raise ValueError("Thumbnail identity or size mismatch")
        data = image.read_bytes()
        if not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
            raise ValueError("Invalid recording thumbnail")
        return row, data
