from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from recording_playback import RecordingPlayback, filter_summary, calendar_date


class PlaybackQueryTests(unittest.TestCase):
    def test_actual_ios_face_player_bare_stream_and_unscoped_queries(self):
        from playback_media import routed_query
        other = '10:00:00:00:00:04'
        self.storage.devices[other] = {'device_model': 'C400', 'hardware_version': '2.0',
            'device_id': 'owned-c400', 'hub_storage_enabled': True}
        self.write('event-other', other, self.start + 60)
        handler = SimpleNamespace(path='/stream', server=SimpleNamespace(playback=self.playback))
        query = routed_query(handler, {'channels': [0], 'start_time': str(self.start),
            'player_id': 'ios-player', 'scale': '1/1', 'auto_seek': '1',
            'audio_config': {}, 'client_id': 1, 'track_id': 0, 'vod_type': 0})
        row, files, offset, duration = self.playback.stream_files(query)
        self.assertEqual((row['camera_mac'], len(files), offset, duration), (self.mac, 1, 0, 20))
        for method, section in (('searchVideoWithUTC', 'search_video_with_utc'),
                                ('searchDetectionList', 'search_detection_list')):
            reply = self.query(method, section, start_time=self.start - 1,
                end_time=self.start + 100, channel=0, start_index=0, end_index=99)
            self.assertEqual(reply['error_code'], 0)
            result = reply['result']['playback']
            self.assertEqual(len(result.get('search_video_results', result.get('search_detection_list'))), 2)
        reply = self.query('searchDateWithVideo', 'search_year_utility',
            start_date='20261101', end_date='20261131', channel=[0])
        self.assertEqual(reply['error_code'], 0)
        self.assertEqual(len(reply['result']['playback']['search_results']), 2)
        # Ambiguous sources and unsupported channels stay rejected in the bare hub route.
        self.write('event-conflict', other, self.start)
        with self.assertRaises(ValueError):
            self.playback.select(query)
        for extra in ({'channel': 1}, {'channels': [1]}):
            with self.assertRaises(ValueError):
                self.playback.recordings(extra)

    def test_own_hub_catalog_selects_saved_source_and_rejects_cross_camera_ambiguity(self):
        hub = '10:00:00:00:00:aa'
        self.storage.device_info = {'mac': hub, 'dev_id': 'owned-hub'}
        other = '10:00:00:00:00:04'
        self.storage.devices[other] = {'device_model': 'C400', 'hardware_version': '2.0',
            'device_id': 'owned-c400', 'hub_storage_enabled': True}
        self.write('event-other', other, self.start + 60)
        row, _, _ = self.playback.select({'camera_mac': hub, 'start_time': self.start})
        self.assertEqual(row['camera_mac'], self.mac)
        row, _, _ = self.playback.select({'camera_mac': hub, 'start_time': self.start + 61})
        self.assertEqual(row['camera_mac'], other)
        with self.assertRaises(ValueError):
            self.playback.select({'camera_mac': '10:00:00:00:00:bb', 'start_time': self.start})
        self.write('event-conflict', other, self.start)
        with self.assertRaises(ValueError):
            self.playback.select({'camera_mac': hub, 'start_time': self.start})
        row, _, _ = self.playback.select({'camera_mac': hub, 'child_device_id': 'owned-td21',
                                         'start_time': self.start})
        self.assertEqual(row['camera_mac'], self.mac)

    def test_ios_face_thumbnail_with_hub_uri_reads_the_source_camera_image(self):
        from playback_media import routed_query
        hub = '10:00:00:00:00:aa'
        self.storage.device_info = {'mac': hub, 'dev_id': 'owned-hub'}
        image = self.events/'event-owned.jpg'
        image.write_bytes(b'\xff\xd8owned-source\xff\xd9')
        image.with_suffix('.jpg.json').write_text(json.dumps({'format_version': 1, 'format': 'jpg',
            'camera_mac': self.mac, 'bytes': image.stat().st_size}))
        handler = SimpleNamespace(path='/stream?deviceId=owned-hub&camera_mac=1000000000AA&media_type=2',
                                  server=SimpleNamespace(playback=self.playback))
        query = routed_query(handler, {'channels': [0], 'start_time': str(self.start),
            'end_time': str(self.start), 'download_type': '1', 'media_type': 2})
        row, data = self.playback.thumbnail(query)
        self.assertEqual(row['camera_mac'], self.mac)
        self.assertEqual(data, image.read_bytes())

    def test_disabled_destination_retains_hub_archive_and_explicit_camera_playback(self):
        self.storage.devices[self.mac]['hub_storage_enabled'] = False
        self.assertEqual(len(self.playback.recordings({})), 1)
        rows = self.playback.recordings({'camera_mac': self.mac})
        self.assertEqual(len(rows), 1)
        self.assertFalse(self.storage.devices[self.mac]['hub_storage_enabled'])
        for query in ({'camera_mac': '10:00:00:00:00:04'},
                      {'camera_mac': self.mac, 'child_device_id': 'wrong-camera'}):
            with self.assertRaises(ValueError):
                self.playback.recordings(query)

    def test_continuous_playback_joins_adjacent_segments_but_stops_at_a_real_gap(self):
        for number in (0, 1, 3):
            self.write('event-stream-' + str(number), self.mac, self.start + number * 30)
            index = self.events / ('event-stream-' + str(number) + '.mp4.json')
            metadata = json.loads(index.read_text())
            metadata.update(event_type='continuous', duration=30,
                            source_time_precise=self.start + number * 30 + .25)
            index.write_text(json.dumps(metadata))
        (self.events / 'event-owned.mp4.json').unlink()
        _, files, offset, duration = self.playback.stream_files({'start_time': self.start + 5})
        self.assertEqual([row['path'].stem for row in files], ['event-stream-0', 'event-stream-1'])
        self.assertEqual((offset, duration), (5, 55))
        _, files, _, duration = self.playback.stream_files({'start_time': self.start + 5,
                                                         'end_time': self.start + 10})
        self.assertEqual((len(files), duration), (1, 5))

    def test_continuous_segments_are_timeline_only_and_do_not_mask_event_thumbnails(self):
        self.write('event-continuous', self.mac, self.start - 5)
        index = self.events / 'event-continuous.mp4.json'
        metadata = json.loads(index.read_text())
        metadata.update(event_type='continuous', duration=30)
        metadata.pop('video_pts')
        metadata.pop('rate')
        index.write_text(json.dumps(metadata))
        response = self.query('searchVideoWithUTC', 'search_video_with_utc',
                              start_time=self.start - 5, end_time=self.start + 30)
        results = response['result']['playback']['search_video_results']
        self.assertEqual(results[0]['search_video_results_1']['video_type'], '1')
        self.assertEqual(results[1]['search_video_results_2']['video_type'], '2')
        response = self.query('searchDetectionList', 'search_detection_list',
                              start_time=self.start - 5, end_time=self.start + 30)
        self.assertEqual(response['result']['playback']['total_num'], 1)
        selected, _, _ = self.playback.select({'start_time': self.start})
        self.assertEqual(selected['path'].stem, 'event-owned')

    def test_two_cameras_at_the_same_time_never_mix_recordings(self):
        other = '10:00:00:00:00:04'
        self.storage.devices[other] = {'device_model': 'C400', 'hardware_version': '2.0',
            'device_id': 'owned-c400', 'hub_storage_enabled': True}
        self.write('event-c400', other, self.start)
        self.assertEqual(len(self.playback.recordings({})), 2)
        with self.assertRaises(ValueError):
            self.playback.select({'start_time': self.start})
        self.assertEqual([row['path'].stem for row in self.playback.recordings({'camera_mac': self.mac})], ['event-owned'])
        self.assertEqual([row['path'].stem for row in self.playback.recordings({'child_device_id': 'owned-c400'})], ['event-c400'])
        with self.assertRaises(ValueError):
            self.playback.recordings({'camera_mac': self.mac, 'child_device_id': 'owned-c400'})

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Path(directory.name)
        self.events = self.store / "events"
        self.events.mkdir()
        self.mac = "10:00:00:00:00:02"
        self.storage = SimpleNamespace(lock=threading.Lock(), setup=SimpleNamespace(state={"zone_id": "Europe/Lisbon"}),
            devices={self.mac: {"device_model": "TD21", "device_id": "owned-td21", "hub_storage_enabled": True}})
        self.playback = RecordingPlayback(self.storage)
        for name, kwargs in (("STORE", {"new": self.store}), ("os.path.ismount", {"return_value": True}),
                             ("disk_info", {"return_value": {"status": "normal"}})):
            item = patch("recording_playback." + name, **kwargs)
            item.start()
            self.addCleanup(item.stop)
        self.start = int(datetime(2026, 11, 9, 23, 59, 50, tzinfo=timezone.utc).timestamp())
        self.write("event-owned", self.mac, self.start)

    def write(self, name, mac, start, validated=True):
        path = self.events / (name + ".mp4")
        path.write_bytes(b"validated media")
        Path(str(path) + ".json").write_text(json.dumps({"camera_mac": mac, "source_time": start,
            "bytes": path.stat().st_size, "format_version": 1, "validated_recording": validated,
            "video_pts": list(range(300)), "rate": 15, "event_type": "MD"}))

    def query(self, method, section, **query):
        return self.playback.command(method, {"playback": {section: query}})

    def test_calendar_spans_midnight_and_ignores_foreign_incomplete_and_corrupt_media(self):
        self.write("event-foreign", "10:00:00:00:00:03", self.start - 86400)
        self.write("event-partial", self.mac, self.start - 86400, False)
        (self.events / "event-bad.mp4.json").write_text("bad-json")
        response = self.query("searchDateWithVideo", "search_year_utility",
                              start_date="20261101", end_date="20261130", child_device_mac=self.mac)
        self.assertEqual(response["result"]["playback"]["search_results"], [
            {"search_results_1": {"date": "20261109"}}, {"search_results_2": {"date": "20261110"}}])

    def test_utc_listing_pages_and_overlapping_event_selection(self):
        self.write("event-second", self.mac, self.start + 60)
        response = self.query("searchVideoWithUTC", "search_video_with_utc", start_time=self.start,
                              end_time=self.start + 100, start_index=0, end_index=0)
        result = response["result"]["playback"]
        self.assertEqual(result["to_be_continued"], 1)
        self.assertEqual(result["search_video_results"], [{"search_video_results_1": {
            "startTime": self.start, "endTime": self.start + 20, "channel": 0, "video_type": "2", "vedio_type": "2"}}])
        row, offset, duration = self.playback.select({"start_time": str(self.start + 5), "end_time": str(self.start + 30)})
        self.assertEqual((offset, duration), (5, 15))
        self.assertEqual(row["path"].name, "event-owned.mp4")

    def test_wrong_identity_channel_invalid_range_and_unmounted_store_are_rejected(self):
        for extra in ({"child_device_mac": "10:00:00:00:00:03"}, {"child_device_id": "other"},
                      {"camera_mac": "10:00:00:00:00:03"}, {"channel": 0, "channels": [1]},
                      {"channel": 1}, {"start_time": -1}, {"start_time": self.start + 60}):
            query = {"start_time": self.start, "end_time": self.start + 30, **extra}
            with self.assertRaises(ValueError):
                self.playback.select(query)
        with patch("recording_playback.os.path.ismount", return_value=False):
            self.assertNotEqual(self.query("searchDateWithVideo", "search_year_utility",
                start_date="20261101", end_date="20261130")["error_code"], 0)

    def test_ios_start_only_request_selects_real_remainder_and_validates_camera_mac(self):
        row, offset, duration = self.playback.select({"start_time": str(self.start + 7),
            "camera_mac": self.mac.replace(":", ""), "channels": [0], "scale": "1/1", "auto_seek": "1"})
        self.assertEqual((offset, duration), (7, 13))
        self.assertEqual(row["path"].name, "event-owned.mp4")
        for query in ({"start_time": str(self.start + 20)},
                      {"start_time": str(self.start + 7), "end_time": ""},
                      {"start_time": str(self.start + 7), "camera_mac": "10:00:00:00:00:03"}):
            with self.assertRaises(ValueError):
                self.playback.select(query)

    def test_deleted_symlinked_or_size_changed_files_disappear_from_queries(self):
        path = self.events / "event-owned.mp4"
        path.write_bytes(b"changed")
        self.assertEqual(self.playback.recordings({}), [])
        path.unlink()
        target = self.store / "elsewhere.mp4"
        target.write_bytes(b"validated media")
        path.symlink_to(target)
        self.assertEqual(self.playback.recordings({}), [])

    def test_filter_diagnostics_never_include_identifiers_or_unexpected_values(self):
        result = filter_summary({"start_time": 1794240000, "end_time": "1794326400", "channel": [0],
            "child_device_mac": "private-mac", "child_device_id": "private-id", "player_id": "private-player",
            "date": "private-value", "start_index": False})
        self.assertEqual(result, {"start_time": 1794240000, "end_time": "1794326400", "channel": [0]})

    def test_ios_month_end_sentinel_and_native_wrapped_calendar(self):
        result = self.query("searchDateWithVideo", "search_year_utility", start_date="20261101",
                            end_date="20261131", channel=[0], child_device_id="owned-td21",
                            child_device_mac=self.mac.replace(":", ""))
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(result["result"]["playback"]["search_results"][0], {"search_results_1": {"date": "20261109"}})
        self.assertEqual(calendar_date("20260231", month_end=True).isoformat(), "2026-02-28")
        self.assertEqual(calendar_date("20240231", month_end=True).isoformat(), "2024-02-29")
        for value in ("20261100", "20261132", "20261331", "bad-date"):
            with self.assertRaises(ValueError):
                calendar_date(value, month_end=True)

    def test_ios_event_metadata_has_total_and_pagination_continues_native_table_numbers(self):
        self.write("event-second", self.mac, self.start + 60)
        query = dict(start_time=self.start, end_time=self.start + 100, start_index=1, end_index=99)
        result = self.query("searchVideoWithUTC", "search_video_with_utc", **query)["result"]["playback"]
        self.assertEqual(list(result["search_video_results"][0]), ["search_video_results_2"])
        result = self.query("searchDetectionList", "search_detection_list", **query)["result"]["playback"]
        self.assertEqual(result["total_num"], 2)
        self.assertEqual(len(result["search_detection_list"]), 1)

    def test_detected_motion_events_are_enabled_and_not_labelled_as_timed_recordings(self):
        self.write("event-unknown", self.mac, self.start + 60)
        index = self.events / "event-unknown.mp4.json"
        details = json.loads(index.read_text())
        details["event_type"] = ""
        index.write_text(json.dumps(details))
        result = self.query("searchDetectionList", "search_detection_list", start_time=self.start,
                            end_time=self.start + 100)["result"]["playback"]
        self.assertTrue(result["snapshot_enable"])
        self.assertEqual(result["total_num"], 1)
        self.assertEqual(result["search_detection_list"][0]["alarm_type"], 2)
        self.assertEqual(result["search_detection_list"][0]["file_id"], str(self.start))

    def test_person_detection_is_listed_with_its_own_alarm_type(self):
        self.write("event-person", self.mac, self.start + 60)
        index = self.events / "event-person.mp4.json"
        details = json.loads(index.read_text())
        details["event_type"] = "PD"
        index.write_text(json.dumps(details))
        result = self.query("searchDetectionList", "search_detection_list", start_time=self.start,
                            end_time=self.start + 100)["result"]["playback"]
        self.assertEqual(result["total_num"], 2)
        self.assertEqual([row["alarm_type"] for row in result["search_detection_list"]], [2, 6])
        self.assertEqual(result["search_detection_list"][1]["file_id"], str(self.start + 60))

    def test_thumbnail_requires_matching_validated_private_pair_and_never_accepts_client_paths(self):
        query = {"start_time": str(self.start), "camera_mac": self.mac, "file_id": "../../other.jpg"}
        image = self.events / "event-owned.jpg"
        image.write_bytes(b"\xff\xd8owned\xff\xd9")
        index = image.with_suffix(".jpg.json")
        details = {"format_version": 1, "format": "jpg", "camera_mac": self.mac, "bytes": image.stat().st_size}
        index.write_text(json.dumps(details))
        self.assertEqual(self.playback.thumbnail(query)[1], image.read_bytes())
        details["camera_mac"] = "10:00:00:00:00:03"
        index.write_text(json.dumps(details))
        with self.assertRaises(ValueError):
            self.playback.thumbnail(query)
        index.write_text(json.dumps({**details, "camera_mac": self.mac}))
        image.unlink()
        outside = self.store / "outside.jpg"
        outside.write_bytes(b"\xff\xd8owned\xff\xd9")
        image.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.playback.thumbnail(query)

    def test_thumbnail_ignores_video_end_range_but_video_playback_still_validates_it(self):
        image = self.events / "event-owned.jpg"
        image.write_bytes(b"\xff\xd8owned\xff\xd9")
        image.with_suffix(".jpg.json").write_text(json.dumps({"format_version": 1, "format": "jpg",
            "camera_mac": self.mac, "bytes": image.stat().st_size}))
        for end in (0, "0", str(self.start)):
            query = {"start_time": str(self.start), "end_time": end, "channels": [0]}
            self.assertEqual(self.playback.thumbnail(query)[1], image.read_bytes())
            with self.assertRaises(ValueError):
                self.playback.select(query)
