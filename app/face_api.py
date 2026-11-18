"""Experimental native Tapo face APIs over the private DuckDB registry."""
import base64
import logging
import json
import re
import threading
import time
from datetime import datetime, timezone

from face_database import MAX_PROFILES, profile_fields
from recording_retention import activity, completed_group
from camera_media import STORE
from camera_registry import camera_supported, normalize_mac

LOG = logging.getLogger("tapo-hub-lab")
METHODS = {"getFaceDetectionConfig", "setFaceDetectionConfig", "searchFacesInfo", "setFaceInfo",
           "doFaceInfoAdd", "doFaceInfoAddPacketized", "doFaceInfoGet", "getFaceSimilarityInfo",
           "getFaceDetectionStatistics"}
METHODS.add("doSearchFaceDetectionVideo")
METHODS.update(("getFaceNotificationConfig", "setFaceNotificationConfig"))
# Local authenticated diagnostics, not an advertised native Tapo feature.
METHODS.add('getLocalFaceAnalysisStatus')


class FaceAPI:
    def __init__(self, database, client, playback):
        self.db, self.client, self.playback = database, client, playback
        self.lock = threading.RLock()
        self.packets = {}
        self.last_camera = None
        self.retry_after = {}
        self.profile_refresh_time = int(time.time() * 1000)

    def config(self):
        return {"enabled": "on" if self.db.enabled else "off", "sensitivity": "medium",
                "tags": ["familiar", "stranger"], "max_familiar_face_num": str(MAX_PROFILES),
                "max_stranger_face_num": str(MAX_PROFILES), "max_faceinfo_bytes": 24_000,
                # This field selects delegation to another hub, not local AI availability.
                # Native format 1 is raw NV12; the worker accepts encoded images (format 2).
                "pic_format": 2, "hub_face_ai_enhance": 0}

    def cameras(self, query=None, *, history=False):
        query = query or {}
        with self.playback.storage.lock:
            cameras = {mac: dict(record) for mac, record in self.playback.storage.devices.items()
                       if camera_supported(record) and (history or record.get("hub_storage_enabled"))}
        requested = False
        for key in ("child_device_mac", "camera_mac", "mac"):
            if key in query:
                values = query[key] if key == 'mac' and isinstance(query[key], list) else [query[key]]
                if len(values) > 16:
                    raise ValueError('Too many face camera selectors')
                if not values:
                    continue
                requested = True
                selected = {normalize_mac(value) for value in values}
                hub_mac = getattr(self.playback.storage, 'device_info', {}).get('mac')
                if history and query.get('det_origin') == 1 and hub_mac and selected == {normalize_mac(hub_mac)}:
                    # iOS scopes hub-generated detections by the storage hub, not a child camera.
                    continue
                if not selected.issubset(cameras):
                    raise ValueError('Unknown or conflicting face camera selectors')
                cameras = {m: r for m, r in cameras.items() if m in selected}
        for key in ("child_device_id", "device_id", "dev_id"):
            if key in query:
                requested = True
                if not isinstance(query[key], str) or not query[key]:
                    raise ValueError("Invalid face camera selector")
                cameras = {m: r for m, r in cameras.items() if r["device_id"] == query[key]}
        if requested and not cameras:
            raise ValueError("Unknown or conflicting face camera selectors")
        return cameras

    def recordings(self, query=None, *, history=False):
        rows = []
        for mac, camera in self.cameras(query, history=history).items():
            rows.extend({**row, "camera_mac": mac, "device_id": camera["device_id"],
                         "device_model": camera["device_model"]}
                        for row in self.playback.recordings({"child_device_mac": mac}))
        return sorted(rows, key=lambda row: (row["start"], row["file_id"]))

    def media_photos(self, query):
        from recording_playback import integer
        if not isinstance(query, dict) or query.get("type") != "get_face":
            raise ValueError("Unsupported face image request")
        ids = query.get("face_id")
        if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_PROFILES:
            raise ValueError("Invalid face image batch")
        ids = [integer(key, 1, 2**63-1) for key in ids]
        existing = {row["face_id"] for row in self.db.search(ids=ids, limit=MAX_PROFILES)}
        return [(str(key), self.db.photo(key) if key in existing else None) for key in ids]

    def enroll(self, query):
        name, tag = profile_fields(query.get("name", ""), query.get("tag", "familiar"))
        encoded = query.get("face_info")
        if not isinstance(encoded, str) or not 1 <= len(encoded) <= 1_400_000:
            raise ValueError("Invalid face image")
        data = base64.b64decode(encoded, validate=True)
        request = {"operation": "image", "image": encoded}
        width, height = query.get("width"), query.get("height")
        if not data.startswith((b"\xff\xd8", b"\x89PNG\r\n\x1a\n")):
            if (type(width) is int and type(height) is int and 32 <= width <= 4096
                    and 32 <= height <= 4096 and width % 2 == height % 2 == 0
                    and len(data) == width * height * 3 // 2):
                request.update(image_format="nv12", width=width, height=height)
            elif len(data) >= 12 and data[4:8] == b"ftyp":
                LOG.info("FACE enrollment encoded HEIF container received; decoder support unverified")
        LOG.info("FACE enrollment image_format=%s bytes=%d", request.get("image_format", "encoded"), len(data))
        faces = self.client.call(request)["faces"]
        if len(faces) != 1:
            raise ValueError("Enrollment requires one face")
        face = faces[0]
        key = self.db.add(name, tag, base64.b64decode(face["image"], validate=True), face["embedding"], verified=True)
        return {"face_id": key, "add_time": int(time.time() * 1000)}

    def packet(self, query):
        req, idx, total = query["req_id"], query["pkt_idx"], query["pkt_total"]
        if (not isinstance(req, str) or not 1 <= len(req) <= 64 or type(idx) is not int
                or type(total) is not int or not 1 <= total <= 32 or not 0 <= idx <= total):
            raise ValueError("Invalid face packet")
        chunk = query["face_info"]
        if not isinstance(chunk, str) or len(chunk) > 60_000:
            raise ValueError("Face packet too large")
        now = time.monotonic()
        with self.lock:
            self.packets = {k: v for k, v in self.packets.items() if now - v["time"] < 60}
            if req not in self.packets:
                if idx not in (0, 1) or len(self.packets) >= 4:
                    raise ValueError("Invalid first face packet")
                self.packets[req] = {"time": now, "first": idx, "total": total, "query": dict(query), "chunks": []}
            pending = self.packets[req]
            if total != pending["total"] or idx != pending["first"] + len(pending["chunks"]):
                raise ValueError("Face packet out of order")
            if sum(map(len, pending["chunks"])) + len(chunk) > 1_400_000:
                self.packets.pop(req)
                raise ValueError("Face packet sequence too large")
            pending["chunks"].append(chunk)
            # Native clients take the first non-null face_id as the final enrollment result.
            response = {"pkt_idx": idx}
            if len(pending["chunks"]) == total:
                self.packets.pop(req)
                response.update(self.enroll({**pending["query"], "face_info": "".join(pending["chunks"])}))
            return response

    def command(self, method, params):
        try:
            with activity():
                return self._command(method, params)
        except (OSError, ValueError):
            return {"error_code": -40101}

    def _command(self, method, params):
        stage = 'schema'
        try:
            if method == 'getLocalFaceAnalysisStatus':
                query = params['face_detection']['analysis_status']
                key = query['file_id']
                if not isinstance(key, str) or not re.fullmatch(r'event-[0-9a-f]{24}', key):
                    raise ValueError('Invalid recording key')
                if not any(row['file_id'] == key for row in self.recordings(query)):
                    raise ValueError('No retained recording for the selected camera')
                analyzed = self.db.analyzed(key)
                retry = max(0, int(self.retry_after.get(key, 0) - time.monotonic()))
                state = ('complete' if analyzed else 'disabled' if not self.db.enabled
                         else 'retry_deferred' if retry else 'pending')
                return {'error_code': 0, 'result': {'face_detection': {'analysis_status': {
                    'state': state, 'analyzed': analyzed, 'retry_in_seconds': retry,
                    **self.db.event_face_counts(key)}}}}
            if method == "doSearchFaceDetectionVideo":
                from recording_playback import integer
                query = params["playback"]["action_search_face_detection_video"]
                filters = {k: v for k, v in query.items() if k in ('start_time', 'end_time', 'start_index', 'end_index', 'det_origin')
                           and type(v) is int and abs(v) <= 10**15}
                kinds = []
                known = self.cameras(history=True)
                hub_mac = getattr(self.playback.storage, 'device_info', {}).get('mac')
                for value in query.get('mac', []) if isinstance(query.get('mac', []), list) else [query['mac']]:
                    try:
                        mac = normalize_mac(value)
                        kinds.append('camera' if mac in known else 'hub' if hub_mac and mac == normalize_mac(hub_mac) else 'unknown')
                    except ValueError:
                        kinds.append('invalid')
                LOG.info('FACE history filters=%s mac_kinds=%s face_id_positive=%s',
                         json.dumps(filters, separators=(',', ':')), kinds[:16],
                         type(query.get('face_id')) is int and query['face_id'] > 0)
                stage = 'face_id'
                face_id = integer(query["face_id"], 1)
                stage = 'time_range'
                start, end = integer(query["start_time"]), integer(query["end_time"])
                stage = 'pagination'
                first = integer(query.get("start_index", 0), high=10000)
                last = integer(query.get("end_index", first + 99), first, 10000)
                if end < start:
                    raise ValueError("Invalid face event range")
                keys = {key for key, _ in self.db.events(face_id)}
                stage = 'camera_or_recordings'
                with activity():
                    rows = [row for row in self.recordings(query, history=True) if row["file_id"] in keys
                            and row["start"] <= end and row["end"] > start]
                rows = rows[first:min(last + 1, first + 100)]
                LOG.info('FACE history result recording_count=%d', len(rows))
                return {"error_code": 0, "result": {"playback": {"action_search_face_detection_video": {
                    "search_face_detection_video_result": [{"dev_id": row["device_id"], "mac": row["camera_mac"],
                        "startTime": row["start"], "endTime": row["end"], "alarm_type": 6} for row in rows]}}}}
            section = params["face_detection"]
            if not isinstance(section, dict):
                raise ValueError("Invalid face schema")
            if method == "getFaceNotificationConfig":
                from face_notifications import DEFAULT
                requested = section.get("device_list", [])
                if (not isinstance(requested, list) or len(requested) > 16
                        or any(not isinstance(item, dict) or not isinstance(item.get("device_id"), str)
                               for item in requested)):
                    raise ValueError("Invalid notification device filter")
                selected = {item["device_id"] for item in requested}
                cameras = {mac: record for mac, record in self.cameras(section).items()
                           if not selected or record["device_id"] in selected}
                configs = [self.db.notification_config(mac) for mac in cameras]
                # Native delivery is still unavailable; do not claim push works for new cameras.
                result = {"face_notification": {"familiar_global": "off", "stranger_global": "off"},
                          "notification": {"device_list": [{"device_id": record["device_id"],
                              "face_notification": "off", "familiar_enable": config["familiar_enable"],
                              "stranger_enable": config["stranger_enable"], "face_id": config["face_id"],
                              "alert_limit": config["alert_limit"]}
                              for record, config in zip(cameras.values(), configs)]},
                          "notify_list": configs[0] if configs and all(c == configs[0] for c in configs) else dict(DEFAULT)}
            elif method == "setFaceNotificationConfig":
                from face_notifications import configuration
                if "set_notify_list" not in section:
                    return {"error_code": -40210}
                cameras = self.cameras(section)
                if not cameras:
                    raise ValueError("No active face cameras")
                configs = {mac: configuration(section["set_notify_list"], self.db.notification_config(mac))
                           for mac in cameras}
                if any(c["msg_push_enabled"] == "on" for c in configs.values()):
                    LOG.info("FACE native notification delivery unavailable; enable not acknowledged")
                    return {"error_code": -40210}
                for mac, config in configs.items():
                    self.db.save_notification_config(mac, config)
                result = {}
            elif method == "getFaceDetectionConfig":
                result = {"detection": self.config()}
            elif method == "setFaceDetectionConfig":
                query = section["detection"]
                if not isinstance(query, dict) or set(query) - {"enabled"} or query.get("enabled") not in ("on", "off"):
                    raise ValueError("Unsupported face setting")
                self.db.set_enabled(query["enabled"] == "on")
                result = {}
            elif method == "searchFacesInfo":
                query = section["search_faces_info"]
                limit = query.get("trans_limit", 100)
                if type(limit) is not int or not 1 <= limit <= MAX_PROFILES:
                    raise ValueError("Invalid face page limit")
                if query.get("strategy", "select") != "select":
                    raise ValueError("Unsupported face search strategy")
                updated_after = query.get('update_time', 0)
                if type(updated_after) is not int or updated_after < 0:
                    raise ValueError('Invalid face update cursor')
                # Refresh each client's cached display times once after a server restart.
                if updated_after < self.profile_refresh_time:
                    updated_after = 0
                rows = self.db.search(tags=query.get("tag"), ids=query.get("face_id"),
                    updated_after=updated_after, limit=MAX_PROFILES)
                result = {"search_faces_info_result": {"faces_infos": rows[:limit], "total_num": len(rows),
                                                       "search_time": int(time.time() * 1000)}}
            elif method == "doFaceInfoAdd":
                result = {"action_face_info_add": self.enroll(section["action_face_info_add"])}
            elif method == "doFaceInfoAddPacketized":
                result = {"action_face_info_add_packetized": self.packet(section["action_face_info_add_packetized"])}
            elif method == "doFaceInfoGet":
                ids = section["action_face_info_get"]["face_id"]
                if not isinstance(ids, list) or not 1 <= len(ids) <= 8:
                    raise ValueError("Invalid face photo request")
                result = {"action_face_info_get": [{"face_id": key, "face_status": "exist",
                    "face_info": base64.b64encode(self.db.photo(key)).decode()} for key in ids]}
            elif method == "setFaceInfo":
                commands = section["set_face_info"]["commands"]
                self.db.apply_commands(commands)
                result = {}
            elif method == "getFaceSimilarityInfo":
                # No suggested merges until similarity grouping is implemented.
                result = {"user_operatable_groups": {}}
            elif method == "getFaceDetectionStatistics":
                query = section["get_face_detection_statistics"]
                requested = query.get("search_faces", [])
                if not isinstance(requested, list) or len(requested) > MAX_PROFILES:
                    raise ValueError("Invalid face statistics request")
                ids = [q["face_id"] for q in requested]
                rows = self.db.search(ids=ids, limit=MAX_PROFILES)
                start, end = query.get("start_utc_day", 0), query.get("end_utc_day", 99991231)
                if type(start) is not int or type(end) is not int or end < start:
                    raise ValueError("Invalid statistics range")
                statistics = []
                macs = list(self.cameras(query, history=True))
                recordings = {row["file_id"]: row for row in self.recordings(query, history=True)}
                for row in rows:
                    days = {}
                    for event_key, stamp in self.db.events(row["face_id"]):
                        event = recordings.get(event_key)
                        if event is None:
                            continue
                        date = datetime.fromtimestamp(stamp, timezone.utc)
                        day = int(date.strftime("%Y%m%d"))
                        if start <= day <= end:
                            cameras = days.setdefault(day, {}).setdefault(date.hour, {})
                            index = macs.index(event["camera_mac"])
                            cameras[index] = cameras.get(index, 0) + 1
                    statistics.append({"face_id": row["face_id"], "is_stranger": row["tag"] == "stranger",
                        "status": "active", "appearance_time": sum(sum(sum(c.values()) for c in hours.values())
                                                                  for hours in days.values()),
                        "appearance_results": [{"utc_day": day, "serial_num": 0, "data_per_hour": [
                            {"time_hour": hour, "statistics": [{"mac": index, "times": count}
                                for index, count in sorted(cameras.items())]}
                            for hour, cameras in sorted(days[day].items())]}
                                               for day in sorted(days)]})
                result = {"get_fd_statistic_results": {"mac_list": macs, "fd_statistics": statistics}}
            else:
                return {"error_code": -40210}
            return {"error_code": 0, "result": {"face_detection": result}}
        except (ValueError, TypeError, KeyError, OSError) as error:
            if method == 'doSearchFaceDetectionVideo':
                LOG.info('FACE history rejected stage=%s reason=%s', stage, type(error).__name__)
            return {"error_code": -40209}
        except Exception as error:
            LOG.info("FACE API failed method=%s reason=%s", method, type(error).__name__)
            return {"error_code": -40101}

    def process_events(self):
        if not self.db.enabled:
            return
        with activity():
            for key, image in self.db.pending_embeddings():
                result = self.client.call({"operation": "reembed", "image": base64.b64encode(image).decode()})
                self.db.replace_embedding(key, result["embedding"])
            if self.db.pending_embeddings():
                return
            rows = self.recordings()
            retained = {row["file_id"] for row in rows}
            # Unlinking a camera must not erase face history while its footage is retained.
            for key in self.db.recording_keys() - retained:
                if (STORE / 'events' / (key + '.mp4')).is_file() and completed_group(key) is not None:
                    retained.add(key)
            self.db.prune_events(retained)
            pending_keys = self.db.unanalyzed({row["file_id"] for row in rows})
            self.retry_after = {key: deadline for key, deadline in self.retry_after.items()
                                if key in retained and deadline > time.monotonic()}
            pending = [row for row in rows if row["file_id"] in pending_keys
                       and row["file_id"] not in self.retry_after]
            cameras = list(self.cameras())
            if self.last_camera in cameras:
                index = cameras.index(self.last_camera) + 1
                cameras = cameras[index:] + cameras[:index]
            for mac in cameras:
                candidates = [row for row in pending if row["camera_mac"] == mac]
                if candidates:
                    row = candidates[0]
                    break
            else:
                return False
            self.last_camera = row["camera_mac"]
            if not self.db.enabled:
                return False
            try:
                faces, cursor = [], 0
                while self.db.enabled:
                    result = self.client.call({"operation": "clip", "path": str(row["path"]), "sample_start": cursor})
                    faces.extend(result["faces"][:20-len(faces)])
                    next_cursor = result.get("next_sample")
                    if next_cursor is None or len(faces) >= 20:
                        break
                    if type(next_cursor) is not int or not cursor < next_cursor < 24:
                        raise ValueError("Invalid face analysis continuation")
                    cursor = next_cursor
                    # Let pending gallery/enrollment requests use the worker between four-frame batches.
                    time.sleep(0.01)
                if not self.db.enabled:
                    return False
                for face in faces:
                    tags = ("familiar", "stranger") if face.get("recognizable", True) else ("stranger",)
                    key = self.db.match(face["embedding"], tags=tags)
                    if key is None:
                        key = self.db.add("", "stranger", base64.b64decode(face["image"], validate=True), face["embedding"])
                    self.db.link(key, row["file_id"], row["start"])
                    self.db.queue_familiar_notification(row["camera_mac"], key, row["file_id"], row["start"])
                self.db.mark_analyzed(row["file_id"])
            except Exception:
                self.retry_after[row["file_id"]] = time.monotonic() + 300
                LOG.info("FACE recording deferred model=%s retry_seconds=300", row["device_model"])
                raise
            LOG.info("FACE completed recording analyzed model=%s candidates=%d", row["device_model"], len(faces))
            # One clip per pass releases retention and interactive requests between clips.
            return True

    def watch(self):
        while True:
            processed = False
            try:
                processed = self.process_events()
            except Exception as error:
                processed = bool(self.retry_after)
                LOG.info("FACE background processing deferred reason=%s", type(error).__name__)
            time.sleep(1 if processed else 30)
