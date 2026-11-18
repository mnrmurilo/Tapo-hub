import base64
from contextlib import nullcontext
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from face_api import FaceAPI
from face_database import FaceDatabase, DIMENSIONS
from face_inference import message, align_face, Engine, sample_frames
from hub_lab import Diagnostics


@unittest.skipUnless(importlib.util.find_spec("duckdb"), "Optional DuckDB dependency not installed")
class FaceAPITests(unittest.TestCase):
    def setUp(self):
        lease = patch("face_api.activity", side_effect=lambda: nullcontext())
        lease.start()
        self.addCleanup(lease.stop)
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.db = FaceDatabase(Path(self.work.name) / "faces" / "test.duckdb")
        self.addCleanup(self.db.close)
        self.image = b"\xff\xd8test\xff\xd9"
        self.face = {"embedding": [1.0] + [0.0] * (DIMENSIONS - 1), "image": base64.b64encode(self.image).decode()}
        self.client = Mock()
        self.client.call.return_value = {"faces": [self.face]}
        self.storage = SimpleNamespace(lock=threading.Lock(), devices={"10:00:00:00:00:02": {
            "device_model": "TD21", "device_id": "owned-test", "hub_storage_enabled": True}})
        self.playback = SimpleNamespace(storage=self.storage, recordings=Mock(return_value=[]),
                                        camera=lambda query: "10:00:00:00:00:02")
        self.api = FaceAPI(self.db, self.client, self.playback)

    def call(self, method, section, query):
        return self.api.command(method, {"face_detection": {section: query}})

    def test_enrollment_advertises_native_jpeg_format_instead_of_raw_nv12(self):
        result = self.api.command("getFaceDetectionConfig", {"face_detection": {"name": ["detection"]}})
        self.assertEqual(result["result"]["face_detection"]["detection"]["pic_format"], 2)

    def test_face_display_time_is_source_video_seconds_and_ios_range_finds_it(self):
        key = self.enroll()
        stamp = 1794468303
        row = {'file_id': 'event-' + 'b' * 24, 'path': Path('owned.mp4'),
               'start': stamp, 'end': stamp + 10}
        self.db.link(key, row['file_id'], stamp)
        self.playback.recordings.return_value = [row]
        profiles = self.call('searchFacesInfo', 'search_faces_info', {'strategy': 'select', 'update_time': 0})
        profile = profiles['result']['face_detection']['search_faces_info_result']['faces_infos'][0]
        self.assertEqual(profile['fresh_time'], stamp)
        self.assertLess(profile['create_time'], 4_102_444_800)
        # Keep the existing incremental-update cursor intact.
        self.assertGreater(profile['modify_time'], 1_000_000_000_000)
        response = self.api.command('doSearchFaceDetectionVideo', {'playback': {
            'action_search_face_detection_video': {'face_id': key, 'mac': ['100000000002'],
                'id': 0, 'det_origin': 0, 'start_index': 0, 'end_index': 99,
                'start_time': profile['fresh_time'] - 60, 'end_time': profile['fresh_time'] + 60}}})
        self.assertEqual(response['error_code'], 0)
        found = response['result']['playback']['action_search_face_detection_video']['search_face_detection_video_result']
        self.assertEqual(found[0]['startTime'], stamp)

    def test_restart_refreshes_cached_face_times_then_resumes_incremental_sync(self):
        self.enroll()
        self.db.connection.execute('UPDATE faces SET modified=?', [self.api.profile_refresh_time - 1000])
        old_cursor = self.api.profile_refresh_time - 1
        response = self.call('searchFacesInfo', 'search_faces_info', {'update_time': old_cursor})
        result = response['result']['face_detection']['search_faces_info_result']
        self.assertEqual(len(result['faces_infos']), 1)
        response = self.call('searchFacesInfo', 'search_faces_info', {'update_time': result['search_time']})
        self.assertEqual(response['result']['face_detection']['search_faces_info_result']['faces_infos'], [])
        self.assertNotEqual(self.call('searchFacesInfo', 'search_faces_info', {'update_time': True})['error_code'], 0)

    def test_real_face_query_rejection_logs_safe_stage_without_identifiers(self):
        key = self.enroll()
        query = {'face_id': key, 'mac': ['100000000002'], 'start_time': 1794468303,
                 'end_time': 1794468400, 'start_index': 0, 'end_index': -1,
                 'password': 'private-diagnostic-test'}
        with self.assertLogs('tapo-hub-lab', level='INFO') as logs:
            result = self.api.command('doSearchFaceDetectionVideo', {
                'playback': {'action_search_face_detection_video': query}})
        self.assertEqual(result['error_code'], -40209)
        text = '\n'.join(logs.output)
        self.assertIn('stage=pagination', text)
        self.assertNotIn('100000000002', text)
        self.assertNotIn('private-diagnostic-test', text)

    def test_actual_ios_hub_origin_query_uses_own_hub_scope_and_returns_source_camera(self):
        rows = self.three_cameras()
        face = self.enroll()
        hub = '10:00:00:00:00:aa'
        self.storage.device_info = {'mac': hub}
        event = rows['10:00:00:00:00:02'][0]
        self.db.link(face, event['file_id'], event['start'])
        query = {'face_id': face, 'mac': [hub.replace(':', '').upper()],
                 'start_time': 0, 'end_time': 1794526159, 'start_index': 0,
                 'end_index': 19, 'det_origin': 1, 'id': 1}
        response = self.api.command('doSearchFaceDetectionVideo', {
            'playback': {'action_search_face_detection_video': query}})
        self.assertEqual(response['error_code'], 0)
        found = response['result']['playback']['action_search_face_detection_video']['search_face_detection_video_result']
        self.assertEqual([(r['mac'], r['dev_id']) for r in found], [('10:00:00:00:00:02', 'owned-test')])
        for invalid in ({**query, 'mac': ['1000000000bb']}, {**query, 'det_origin': 0},
                        {**query, 'mac': [hub, '100000000002']}):
            result = self.api.command('doSearchFaceDetectionVideo', {
                'playback': {'action_search_face_detection_video': invalid}})
            self.assertNotEqual(result['error_code'], 0)

    def test_native_raw_enrollment_forwards_exact_validated_nv12_layout(self):
        self.client.call.return_value = {"faces": [self.face]}
        raw = base64.b64encode(bytes(200*200*3//2)).decode()
        result = self.call("doFaceInfoAdd", "action_face_info_add", {
            "name": "", "tag": "familiar", "face_info": raw, "width": 200, "height": 200})
        self.assertEqual(result["error_code"], 0)
        request = self.client.call.call_args.args[0]
        self.assertEqual((request["image_format"], request["width"], request["height"]), ("nv12", 200, 200))

    def test_media_photo_batch_preserves_order_and_marks_missing_profiles(self):
        key = self.enroll()
        result = self.api.media_photos({"type": "get_face", "face_id": [str(key), "9999"]})
        self.assertEqual(result, [(str(key), self.image), ("9999", None)])
        self.db.delete(key)
        self.assertEqual(self.api.media_photos({"type": "get_face", "face_id": [str(key)]}), [(str(key), None)])
        for query in ({"type": "get_face", "face_id": []}, {"type": "get_face", "face_id": [True]},
                      {"type": "get_face", "face_id": ["../private"]}, {"type": "get_wallpaper", "face_id": [1]}):
            with self.subTest(query=query), self.assertRaises(ValueError):
                self.api.media_photos(query)

    def three_cameras(self):
        self.storage.devices['10:00:00:00:00:04'] = {'device_model': 'C400', 'hardware_version': '2.0',
            'device_id': 'owned-c400', 'hub_storage_enabled': True}
        self.storage.devices['10:00:00:00:00:06'] = {'device_model': 'TC70', 'hardware_version': '5.0',
            'device_id': 'owned-tc70', 'hub_storage_enabled': True}
        rows = {mac: [{'file_id': 'event-' + str(index)*24,
                      'path': Path(str(index) + '.mp4'), 'start': 1794341500 + index,
                      'end': 1794341510 + index}]
                for index, mac in enumerate(self.storage.devices, 1)}
        self.playback.recordings.side_effect = lambda query: rows[query['child_device_mac']]
        return rows

    def test_all_cameras_share_profiles_and_are_processed_without_continuous_starvation(self):
        rows = self.three_cameras()
        familiar = self.enroll()
        self.client.call.reset_mock()
        self.db.set_enabled(True)
        # TC70 has an older continuous backlog; every other camera must still get a turn.
        rows['10:00:00:00:00:06'].insert(0, {'file_id': 'event-'+'a'*24,
            'path': Path('older-continuous.mp4'), 'start': 1794341400, 'end': 1794341430})
        with patch.object(self.db, 'queue_familiar_notification', wraps=self.db.queue_familiar_notification) as queue:
            for _ in range(3):
                self.assertTrue(self.api.process_events())
            self.assertEqual([call.args[0] for call in queue.call_args_list], list(self.storage.devices))
        self.assertEqual(len(self.db.events(familiar)), 3)
        self.assertEqual(len(self.db.search()), 1)
        self.assertEqual([call.args[0]['path'] for call in self.client.call.call_args_list],
                         ['1.mp4', '2.mp4', 'older-continuous.mp4'])
        self.assertTrue(self.api.process_events())
        self.assertEqual(len(self.db.events(familiar)), 4)
        self.assertFalse(self.api.process_events())

    def test_unknown_collection_history_statistics_and_retention_keep_the_source_camera(self):
        rows = self.three_cameras()
        self.db.set_enabled(True)
        for _ in range(3):
            self.api.process_events()
        profiles = self.db.search(tags=['stranger'])
        self.assertEqual(len(profiles), 1)
        face_id = profiles[0]['face_id']
        def videos(**selectors):
            result = self.api.command('doSearchFaceDetectionVideo', {'playback': {
                'action_search_face_detection_video': {'face_id': face_id, 'start_time': 1794341400,
                                                      'end_time': 1794341600, **selectors}}})
            self.assertEqual(result['error_code'], 0)
            return result['result']['playback']['action_search_face_detection_video']['search_face_detection_video_result']
        found = videos()
        self.assertEqual([(r['mac'], r['dev_id']) for r in found],
                         [(mac, record['device_id']) for mac, record in self.storage.devices.items()])
        self.assertEqual(len(videos(camera_mac='10:00:00:00:00:04')), 1)
        # iOS sends the compact MACs as an array, including for a single camera.
        selected = videos(mac=['100000000004'])
        self.assertEqual([(r['mac'], r['dev_id']) for r in selected],
                         [('10:00:00:00:00:04', 'owned-c400')])
        self.assertEqual(len(videos(mac=['100000000002', '100000000006'])), 2)
        self.assertEqual(len(videos(mac=[])), 3)
        archived_mac = '10:00:00:00:00:06'
        self.storage.devices[archived_mac]['hub_storage_enabled'] = False
        self.assertNotIn(archived_mac, self.api.cameras())
        self.assertEqual(len(videos(mac=['100000000006'])), 1)
        self.assertFalse(self.storage.devices[archived_mac]['hub_storage_enabled'])
        self.storage.devices[archived_mac]['hub_storage_enabled'] = True
        for invalid in ({'mac': ['invalid']}, {'mac': ['100000000008']},
                        {'mac': [False]}, {'mac': ['100000000002'] * 17},
                        {'mac': ['100000000004'], 'device_id': 'owned-tc70'}):
            with self.subTest(selectors=invalid), self.assertRaises(ValueError):
                self.api.cameras(invalid)
        result = self.call('getFaceDetectionStatistics', 'get_face_detection_statistics', {
            'search_faces': [{'face_id': face_id}], 'start_utc_day': 20261110, 'end_utc_day': 20261110})
        stats = result['result']['face_detection']['get_fd_statistic_results']
        self.assertEqual(stats['mac_list'], list(self.storage.devices))
        face = stats['fd_statistics'][0]
        self.assertEqual(face['appearance_time'], 3)
        self.assertEqual(face['appearance_results'][0]['data_per_hour'][0]['statistics'],
                         [{'mac': 0, 'times': 1}, {'mac': 1, 'times': 1}, {'mac': 2, 'times': 1}])
        rows['10:00:00:00:00:06'].clear()
        self.api.process_events()
        self.assertEqual(len(self.db.events(face_id)), 2)
        self.assertEqual(len(self.db.search(tags=['stranger'])), 1)

    def test_notifications_cover_all_cameras_without_claiming_native_delivery(self):
        self.three_cameras()
        query = {'msg_push_enabled': 'off', 'familiar_enable': 'on', 'stranger_enable': 'off',
                 'alert_limit': 3, 'face_id': []}
        self.assertEqual(self.call('setFaceNotificationConfig', 'set_notify_list', query)['error_code'], 0)
        for mac in self.storage.devices:
            self.assertEqual(self.db.notification_config(mac)['alert_limit'], '3')
        result = self.api.command('getFaceNotificationConfig', {'face_detection': {}})
        cameras = result['result']['face_detection']['notification']['device_list']
        self.assertEqual({r['device_id'] for r in cameras}, {'owned-test', 'owned-c400', 'owned-tc70'})
        self.assertTrue(all(r['face_notification'] == 'off' for r in cameras))
        self.assertEqual(self.call('setFaceNotificationConfig', 'set_notify_list',
                                  {**query, 'msg_push_enabled': 'on'})['error_code'], -40210)
        with self.assertRaises(ValueError):
            self.api.cameras({'camera_mac': '10:00:00:00:00:04', 'device_id': 'owned-tc70'})
        self.storage.devices['10:00:00:00:00:04']['hub_storage_enabled'] = False
        self.assertNotIn('10:00:00:00:00:04', self.api.cameras())

    def test_camera_failure_does_not_block_analysis_of_the_other_cameras(self):
        self.three_cameras()
        self.db.set_enabled(True)
        self.client.call.side_effect = [ValueError('worker unavailable'), {'faces': [self.face]}, {'faces': [self.face]}]
        with self.assertRaises(ValueError):
            self.api.process_events()
        self.assertTrue(self.api.process_events())
        self.assertTrue(self.api.process_events())
        self.assertEqual([call.args[0]['path'] for call in self.client.call.call_args_list], ['1.mp4', '2.mp4', '3.mp4'])

    def test_failed_clip_is_deferred_without_blocking_newer_footage_from_same_camera(self):
        first, second = 'event-'+'a'*24, 'event-'+'b'*24
        self.db.set_enabled(True)
        self.playback.recordings.return_value = [
            {'file_id': first, 'path': Path('bad.mp4'), 'start': 1794341500, 'end': 1794341510},
            {'file_id': second, 'path': Path('good.mp4'), 'start': 1794341510, 'end': 1794341520}]
        self.client.call.side_effect = [ValueError('bad decode'), {'faces': []}, {'faces': []}]
        clock = [0]
        with patch('face_api.time.monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(ValueError):
                self.api.process_events()
            self.assertTrue(self.api.process_events())
            self.assertFalse(self.db.analyzed(first))
            self.assertTrue(self.db.analyzed(second))
            self.assertFalse(self.api.process_events())
            clock[0] = 301
            self.assertTrue(self.api.process_events())
        self.assertTrue(self.db.analyzed(first))
        self.assertEqual([call.args[0]['path'] for call in self.client.call.call_args_list],
                         ['bad.mp4', 'good.mp4', 'bad.mp4'])

    def test_read_only_analysis_status_distinguishes_completion_counts_and_camera(self):
        rows = self.three_cameras()
        self.db.set_enabled(True)
        mac = '10:00:00:00:00:06'
        key = rows[mac][0]['file_id']
        def status(camera=mac):
            return self.call('getLocalFaceAnalysisStatus', 'analysis_status', {'file_id': key, 'camera_mac': camera})
        initial = status()['result']['face_detection']['analysis_status']
        self.assertEqual((initial['state'], initial['analyzed'], initial['face_count']), ('pending', False, 0))
        self.db.mark_analyzed(key)
        complete = status()['result']['face_detection']['analysis_status']
        self.assertEqual((complete['state'], complete['analyzed'], complete['face_count']), ('complete', True, 0))
        familiar = self.enroll()
        self.db.link(familiar, key, rows[mac][0]['start'])
        complete = status()['result']['face_detection']['analysis_status']
        self.assertEqual((complete['face_count'], complete['familiar_count'], complete['stranger_count']), (1, 1, 0))
        self.assertNotIn('embedding', str(complete))
        self.assertEqual(status('10:00:00:00:00:02')['error_code'], -40209)

    def test_unlink_keeps_face_links_until_the_recording_is_actually_removed(self):
        self.three_cameras()
        self.db.set_enabled(True)
        face = self.enroll()
        mac, event_id = '10:00:00:00:00:04', '12345'
        key = 'event-' + hashlib.sha256((mac + ':' + event_id).encode()).hexdigest()[:24]
        self.db.link(face, key, 1794341500)
        self.db.mark_analyzed(key)
        self.storage.devices[mac]['hub_storage_enabled'] = False
        store = Path(self.work.name)
        (store / 'events').mkdir()
        media = store / 'events' / (key + '.mp4')
        media.write_bytes(b'validated test video')
        index = media.with_suffix('.mp4.json')
        index.write_text(json.dumps({'event_id': event_id, 'camera_mac': mac, 'format': 'mp4',
            'format_version': 1, 'validated_recording': True, 'bytes': media.stat().st_size,
            'verified_tracks': [{'codec_type': 'video'}]}))
        with patch('face_api.STORE', store), patch('recording_retention.STORE', store):
            self.api.process_events()
            self.assertIn((key, 1794341500), self.db.events(face))
            self.assertTrue(self.db.analyzed(key))
            media.unlink()
            index.unlink()
            self.api.process_events()
        self.assertNotIn((key, 1794341500), self.db.events(face))
        self.assertFalse(self.db.analyzed(key))

    def enroll(self):
        result = self.call("doFaceInfoAdd", "action_face_info_add", {
            "name": "Owned reference", "tag": "familiar", "face_info": self.face["image"]})
        self.assertEqual(result["error_code"], 0)
        return result["result"]["face_detection"]["action_face_info_add"]["face_id"]

    def test_native_enrollment_gallery_photo_edit_delete_and_restart(self):
        key = self.enroll()
        result = self.call("searchFacesInfo", "search_faces_info", {"tag": ["familiar"]})
        rows = result["result"]["face_detection"]["search_faces_info_result"]["faces_infos"]
        self.assertEqual(rows[0]["face_id"], key)
        self.assertNotIn("embedding", str(result))
        result = self.call("doFaceInfoGet", "action_face_info_get", {"face_id": [key]})
        photo = result["result"]["face_detection"]["action_face_info_get"][0]["face_info"]
        self.assertEqual(base64.b64decode(photo), self.image)
        result = self.call("setFaceInfo", "set_face_info", {"commands": [{"operate": "set",
            "ori_face_id": key, "cover": {"name": "Edited", "tag": "stranger"}}]})
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(self.db.search()[0]["name"], "Edited")
        self.assertEqual(self.call("setFaceInfo", "set_face_info", {"commands": [
            {"operate": "del", "ori_face_id": key}]} )["error_code"], 0)
        self.assertEqual(self.db.search(), [])

    def test_packet_enrollment_is_bounded_ordered_and_commits_only_on_last_packet(self):
        data = self.face["image"]
        base = {"req_id": "owned-packet", "pkt_total": 2, "name": "Test", "tag": "familiar"}
        first = {**base, "pkt_idx": 0, "face_info": data[:4]}
        self.assertEqual(self.call("doFaceInfoAddPacketized", "action_face_info_add_packetized", first)["error_code"], 0)
        self.assertEqual(self.db.search(), [])
        last = {**base, "pkt_idx": 1, "face_info": data[4:]}
        self.assertEqual(self.call("doFaceInfoAddPacketized", "action_face_info_add_packetized", last)["error_code"], 0)
        self.assertEqual(len(self.db.search()), 1)
        self.assertNotEqual(self.call("doFaceInfoAddPacketized", "action_face_info_add_packetized",
                                     {**base, "req_id": "other", "pkt_idx": 8, "face_info": data})["error_code"], 0)

    def test_local_recognition_never_selects_external_hub_and_packet_limit_fits_encryption(self):
        import json
        config = self.api.config()
        self.db.set_enabled(True)
        config = self.call("getFaceDetectionConfig", "name", ["detection"])["result"]["face_detection"]["detection"]
        self.assertEqual(config["enabled"], "on")
        self.assertEqual(config["hub_face_ai_enhance"], 0)
        self.assertNotIn("last_device_mac", config)
        request = {"method": "doFaceInfoAddPacketized", "params": {"face_detection": {
            "action_face_info_add_packetized": {"face_info": "A" * config["max_faceinfo_bytes"],
                "req_id": "owned-test", "pkt_idx": 0, "pkt_total": 2}}}}
        padded_ciphertext = ((len(json.dumps(request).encode()) // 16) + 1) * 16
        encoded = len(base64.b64encode(b"x" * padded_ciphertext))
        self.assertLess(encoded + 1024, 65536)
        result = self.call("doFaceInfoAddPacketized", "action_face_info_add_packetized", {
            "req_id": "pending", "pkt_idx": 0, "pkt_total": 2, "face_info": self.face["image"][:4]})
        packet = result["result"]["face_detection"]["action_face_info_add_packetized"]
        self.assertNotIn("face_id", packet)
        self.assertNotIn("add_time", packet)

    def test_merge_moves_links_and_removes_source_biometrics(self):
        first, second = self.enroll(), self.enroll()
        self.db.link(first, "event-" + "a" * 24, 1794341500)
        response = self.call("setFaceInfo", "set_face_info", {"commands": [{"operate": "set",
            "ori_face_id": first, "cover": {"face_id": second}}]})
        self.assertEqual(response["error_code"], 0)
        self.assertEqual(len(self.db.events(second)), 1)
        with self.assertRaises(ValueError):
            self.db.photo(first)

    def test_ios_combine_five_commands_keeps_chosen_photo_and_all_event_links(self):
        target = self.enroll()
        selected_image = self.db.photo(target)
        sources = [self.db.add('', 'stranger', b'\xff\xd8source-' + bytes([i]) + b'\xff\xd9',
                               self.face['embedding']) for i in range(5)]
        events = ['event-' + format(i, '024x') for i in range(5)]
        for source, event in zip(sources, events):
            self.db.link(source, event, 1794341500)
        self.db.link(target, events[0], 1794341500)  # Shared footage is deduplicated.
        response = self.call('setFaceInfo', 'set_face_info', {'commands': [
            {'operate': 'set', 'ori_face_id': source, 'cover': {'face_id': target}}
            for source in sources]})
        self.assertEqual(response['error_code'], 0)
        self.assertEqual(self.db.photo(target), selected_image)
        self.assertEqual([row['face_id'] for row in self.db.search()], [target])
        self.assertEqual({event for event, _ in self.db.events(target)}, set(events))

    def test_face_batch_rejection_restores_earlier_merges_and_profile_edits(self):
        source, target = self.enroll(), self.enroll()
        event = 'event-' + 'e' * 24
        self.db.link(source, event, 1794341500)
        before = self.db.search()
        response = self.call('setFaceInfo', 'set_face_info', {'commands': [
            {'operate': 'set', 'ori_face_id': source, 'cover': {'face_id': target}},
            {'operate': 'verify', 'ori_face_id': target, 'cover': {'name': 'Changed'}},
            {'operate': 'set', 'ori_face_id': 999999, 'cover': {'face_id': target}}]})
        self.assertNotEqual(response['error_code'], 0)
        self.assertEqual(self.db.search(), before)
        self.assertEqual(self.db.events(source), [(event, 1794341500)])
        self.assertEqual(self.db.events(target), [])
        self.assertEqual(self.db.photo(source), self.image)

    def test_face_batch_validation_does_not_commit_partial_deletes(self):
        source, target = self.enroll(), self.enroll()
        for invalid in ([], [{}] * 301, None,
                        [{'operate': 'set', 'ori_face_id': True, 'cover': {'face_id': target}}],
                        [{'operate': 'set', 'ori_face_id': source, 'cover': {'face_id': True}}],
                        [{'operate': 'del', 'ori_face_id': source}, {'operate': 'unknown'}]):
            response = self.call('setFaceInfo', 'set_face_info', {'commands': invalid})
            self.assertNotEqual(response['error_code'], 0)
            self.assertEqual(len(self.db.search()), 2)

    def test_completed_event_processing_is_asynchronous_idempotent_and_retention_aware(self):
        self.db.set_enabled(True)
        row = {"file_id": "event-" + "b" * 24, "path": Path("owned.mp4"), "start": 1794341500, "end": 1794341510}
        self.playback.recordings.return_value = [row]
        with patch("face_api.activity", side_effect=lambda: nullcontext()):
            self.api.process_events()
            self.api.process_events()
        self.assertEqual(self.client.call.call_count, 1)
        profiles = self.db.search()
        self.assertEqual(profiles[0]["tag"], "stranger")
        self.assertFalse(profiles[0]["user_verified"])
        self.assertEqual(len(self.db.events(profiles[0]["face_id"])), 1)
        self.playback.recordings.return_value = []
        with patch("face_api.activity", side_effect=lambda: nullcontext()):
            self.api.process_events()
        self.assertEqual(self.db.events(profiles[0]["face_id"]), [])
        self.assertEqual(len(self.db.search()), 1)

    def test_soft_faces_create_one_unknown_without_identifying_an_enrolled_familiar(self):
        familiar = self.enroll()
        self.db.set_enabled(True)
        self.client.call.return_value = {"faces": [{**self.face, "recognizable": False}]*2}
        self.playback.recordings.return_value = [{"file_id": "event-"+"c"*24,
            "path": Path("owned.mp4"), "start": 1794341500, "end": 1794341510}]
        self.api.process_events()
        strangers = self.db.search(tags=["stranger"])
        self.assertEqual(len(strangers), 1)
        self.assertEqual(len(self.db.events(strangers[0]["face_id"])), 1)
        self.assertEqual(self.db.events(familiar), [])
        self.assertFalse(strangers[0]["user_verified"])

    def test_background_clip_batches_resume_before_marking_the_event_complete(self):
        self.db.set_enabled(True)
        key = "event-"+"d"*24
        self.playback.recordings.return_value = [{"file_id": key, "path": Path("owned.mp4"),
                                                "start": 1794341500, "end": 1794341510}]
        self.client.call.side_effect = [{"faces": [], "next_sample": 4}, {"faces": [self.face], "next_sample": None}]
        self.api.process_events()
        self.assertEqual([call.args[0]["sample_start"] for call in self.client.call.call_args_list], [0, 4])
        self.assertTrue(self.db.analyzed(key))
        self.assertEqual(len(self.db.search(tags=["stranger"])), 1)

    def test_bad_background_cursor_never_marks_an_event_complete(self):
        self.db.set_enabled(True)
        key = "event-"+"d"*24
        self.playback.recordings.return_value = [{"file_id": key, "path": Path("owned.mp4"),
                                                "start": 1794341500, "end": 1794341510}]
        self.client.call.return_value = {"faces": [], "next_sample": 0}
        with self.assertRaises(ValueError):
            self.api.process_events()
        self.assertFalse(self.db.analyzed(key))

    def test_feature_component_requires_live_model_worker_and_real_api(self):
        handler = object.__new__(Diagnostics)
        handler.client_address = ("192.0.2.1", 123)
        handler.server = SimpleNamespace(faces=self.api)
        for ready in (False, True):
            self.client.ready.return_value = ready
            result = handler.dispatch({"method": "getAppComponentList"})
            names = [row["name"] for row in result["result"]["app_component"]["app_component_list"]]
            self.assertEqual("faceDetection" in names, ready)
        result = handler.dispatch({"method": "getFaceDetectionConfig", "params": {"face_detection": {"name": ["detection"]}}})
        self.assertEqual(result["error_code"], 0)

    def test_no_identity_is_created_for_invalid_or_ambiguous_enrollment(self):
        for faces in ([], [self.face, self.face]):
            self.client.call.return_value = {"faces": faces}
            self.assertNotEqual(self.call("doFaceInfoAdd", "action_face_info_add", {
                "face_info": self.face["image"]})["error_code"], 0)
        self.assertEqual(self.db.search(), [])

    def test_event_statistics_and_face_video_search_use_real_linked_recordings(self):
        key = self.enroll()
        start = 1794341500
        row = {"file_id": "event-" + "c" * 24, "path": Path("owned.mp4"), "start": start, "end": start+10}
        self.db.link(key, row["file_id"], start)
        self.playback.recordings.return_value = [row]
        response = self.call("getFaceDetectionStatistics", "get_face_detection_statistics", {
            "search_faces": [{"face_id": key}], "start_utc_day": 20261110, "end_utc_day": 20261110})
        self.assertEqual(response["error_code"], 0)
        result = response["result"]["face_detection"]["get_fd_statistic_results"]
        self.assertEqual(len(result["mac_list"]), 1)
        self.assertEqual(result["fd_statistics"][0]["appearance_time"], 1)
        self.assertEqual(result["fd_statistics"][0]["appearance_results"][0]["data_per_hour"][0]["statistics"][0]["times"], 1)
        self.playback.recordings.return_value = [row]
        with patch("face_api.activity", side_effect=lambda: nullcontext()):
            response = self.api.command("doSearchFaceDetectionVideo", {"playback": {
                "action_search_face_detection_video": {"face_id": key, "start_time": start, "end_time": start+20}}})
        result = response["result"]["playback"]["action_search_face_detection_video"]["search_face_detection_video_result"]
        self.assertEqual(result[0]["startTime"], start)
        self.playback.recordings.return_value = []
        with patch("face_api.activity", side_effect=lambda: nullcontext()):
            response = self.api.command("doSearchFaceDetectionVideo", {"playback": {
                "action_search_face_detection_video": {"face_id": key, "start_time": start, "end_time": start+20}}})
        self.assertEqual(response["result"]["playback"]["action_search_face_detection_video"]["search_face_detection_video_result"], [])

    def test_notification_read_reports_off_and_enable_never_claims_undeliverable_push(self):
        self.db.set_enabled(True)
        result = self.api.command("getFaceNotificationConfig", {"face_detection": {}})
        self.assertEqual(result["error_code"], 0)
        config = result["result"]["face_detection"]
        self.assertEqual(config["face_notification"], {"familiar_global": "off", "stranger_global": "off"})
        self.assertEqual(config["notify_list"]["msg_push_enabled"], "off")
        self.assertEqual(config["notification"]["device_list"][0]["face_notification"], "off")
        result = self.api.command("setFaceNotificationConfig", {"face_detection": {
            "face_notification": {"familiar_global": "on", "stranger_global": "on"}}})
        self.assertEqual(result["error_code"], -40210)
        self.assertTrue(self.db.enabled)
        result = self.api.command("getFaceNotificationConfig", {"face_detection": {"device_list": [
            {"device_id": "not-enrolled"}]}})
        self.assertEqual(result["result"]["face_detection"]["notification"]["device_list"], [])

    def test_actual_ios_notification_schema_persists_disabled_preferences_without_fake_enable(self):
        query = {"msg_push_enabled": "off", "familiar_enable": "on", "stranger_enable": "off",
                 "alert_limit": 3, "face_id": []}
        result = self.call("setFaceNotificationConfig", "set_notify_list", query)
        self.assertEqual(result["error_code"], 0)
        result = self.api.command("getFaceNotificationConfig", {"face_detection": {"name": ["notify_list"]}})
        config = result["result"]["face_detection"]["notify_list"]
        self.assertEqual(config["familiar_enable"], "on")
        self.assertEqual(config["alert_limit"], "3")
        result = self.call("setFaceNotificationConfig", "set_notify_list", {**query, "msg_push_enabled": "on"})
        self.assertEqual(result["error_code"], -40210)
        self.assertEqual(self.db.notification_config("10:00:00:00:00:02")["msg_push_enabled"], "off")


class FaceMessageTests(unittest.TestCase):
    def test_final_frame_seek_failure_decodes_bounded_tail_without_rejecting_valid_clip(self):
        engine = object.__new__(Engine)
        capture = Mock()
        capture.get.side_effect = lambda prop: 450 if prop == 7 else 14.96972788
        position, direct_eof = [0], [False]
        def seek(prop, value):
            position[0] = value
            direct_eof[0] = value == 449
        def read():
            if direct_eof[0] or position[0] >= 450:
                return False, None
            frame = position[0]
            position[0] += 1
            return True, frame
        capture.set.side_effect, capture.read.side_effect = seek, read
        engine.cv = SimpleNamespace(VideoCapture=Mock(return_value=capture), CAP_FFMPEG=1900,
            CAP_PROP_N_THREADS=70, CAP_PROP_FRAME_COUNT=7, CAP_PROP_FPS=5, CAP_PROP_POS_FRAMES=1)
        engine.faces = Mock(return_value=[])
        with tempfile.TemporaryDirectory() as work, patch('camera_media.STORE', Path(work)):
            path = Path(work)/'events'/('event-'+'a'*24+'.mp4')
            path.parent.mkdir()
            path.touch()
            result = engine.process({'operation': 'clip', 'path': str(path),
                                     'sample_start': len(sample_frames(450, 14.96972788)) - 1})
        self.assertEqual(result, {'faces': [], 'next_sample': None})
        engine.faces.assert_called_once_with(449, limit=10)
        self.assertLessEqual(capture.read.call_count, 33)
        capture.release.assert_called_once()

    def test_worker_clip_batch_reads_four_samples_and_releases_capture(self):
        engine = object.__new__(Engine)
        capture = Mock()
        capture.get.side_effect = lambda prop: 300 if prop == 7 else 30
        capture.read.return_value = (True, object())
        engine.cv = SimpleNamespace(VideoCapture=Mock(return_value=capture), CAP_FFMPEG=1900,
            CAP_PROP_N_THREADS=70, CAP_PROP_FRAME_COUNT=7, CAP_PROP_FPS=5, CAP_PROP_POS_FRAMES=1)
        engine.faces = Mock(return_value=[])
        with tempfile.TemporaryDirectory() as work, patch("camera_media.STORE", Path(work)):
            path = Path(work)/"events"/("event-"+"a"*24+".mp4")
            path.parent.mkdir()
            path.touch()
            result = engine.process({"operation": "clip", "path": str(path), "sample_start": 0})
        self.assertEqual(result, {"faces": [], "next_sample": 4})
        self.assertEqual(capture.read.call_count, 4)
        capture.release.assert_called_once()

    def test_clip_samples_cover_opening_and_end_with_a_fixed_budget(self):
        frames = sample_frames(294, 30)
        self.assertEqual(frames[0], 0)
        self.assertEqual(frames[-1], 293)
        self.assertTrue({0, 7, 15, 22, 30, 37, 45, 52}.issubset(frames))
        self.assertLessEqual(len(frames), 24)
        self.assertEqual(sample_frames(1, 30), [0])
        self.assertLessEqual(len(sample_frames(300000, 30)), 24)
        for count, fps in ((0, 30), (10, 0), (float("nan"), 30), (10, float("inf"))):
            with self.assertRaises(ValueError):
                sample_frames(count, fps)

    @unittest.skipUnless(importlib.util.find_spec("cv2"), "Optional OpenCV dependency not installed")
    def test_detector_maps_landmarks_and_face_size_back_to_original_pixels(self):
        import cv2
        import numpy as np
        engine = object.__new__(Engine)
        engine.cv, engine.np = cv2, np
        engine.detector = Mock()
        landmarks = np.array([[40, 40], [70, 40], [55, 55], [45, 70], [65, 70]], dtype=np.float32)
        row = np.array([30, 30, 30, 30, *landmarks.reshape(-1), 0.99], dtype=np.float32)
        engine.detector.detect.return_value = (None, np.array([row]))
        engine.embedding = Mock(return_value=[1.0]+[0.0]*511)
        original = np.zeros((1680, 1680, 3), dtype=np.uint8)
        aligned = np.zeros((112, 112, 3), dtype=np.uint8)
        with patch("face_inference.align_face", return_value=aligned) as align, \
                patch("cv2.Laplacian", return_value=Mock(var=lambda: 33.5)):
            result = engine.faces(original)
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]["recognizable"])
        self.assertIs(align.call_args.args[0], original)
        np.testing.assert_allclose(align.call_args.args[1], landmarks*(1680/1280))
        engine.detector.setInputSize.assert_called_once_with((1280, 1280))
        row[-1] = 0.89
        engine.detector.detect.return_value = (None, np.array([row]))
        self.assertEqual(engine.faces(original), [])

    @unittest.skipUnless(importlib.util.find_spec("cv2"), "Optional OpenCV dependency not installed")
    def test_native_nv12_decodes_pixels_and_rejects_invalid_layouts(self):
        import cv2
        import numpy as np
        engine = object.__new__(Engine)
        engine.cv, engine.np = cv2, np
        engine.faces = Mock(return_value=[{"test": True}])
        query = {"operation": "image", "image_format": "nv12", "width": 200, "height": 200,
                 "image": base64.b64encode(bytes([128])*(200*200*3//2)).decode()}
        self.assertEqual(engine.process(query), {"faces": [{"test": True}]})
        pixels = engine.faces.call_args.args[0]
        self.assertEqual(pixels.shape, (200, 200, 3))
        self.assertEqual(int(np.max(pixels) - np.min(pixels)), 0)
        engine.faces.return_value = [{"recognizable": False}]
        with self.assertRaises(ValueError):
            engine.process(query)
        for changes in ({"width": True}, {"width": 199}, {"height": 4098},
                        {"height": 202}, {"operation": "reembed"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                engine.process({**query, **changes})

    def test_worker_protocol_rejects_oversized_and_truncated_messages(self):
        for payload in (b"", struct.pack("!I", 2_000_001), struct.pack("!I", 5) + b"{}"):
            with self.assertRaises(ValueError):
                message(io.BytesIO(payload))
        self.assertEqual(message(io.BytesIO(struct.pack("!I", 2) + b"{}")), {})

    @unittest.skipUnless(importlib.util.find_spec("cv2"), "Optional OpenCV dependency not installed")
    def test_arcface_alignment_preserves_canonical_face_and_rejects_bad_landmarks(self):
        import numpy as np
        frame = np.arange(112*112*3, dtype=np.uint8).reshape(112, 112, 3)
        canonical = [[38.2946,51.6963],[73.5318,51.5014],[56.0252,71.7366],
                     [41.5493,92.3655],[70.7299,92.2041]]
        self.assertTrue(np.array_equal(align_face(frame, canonical), frame))
        for invalid in ([], [[0, 0]] * 5, [[float("nan"), 0]] * 5):
            with self.assertRaises(ValueError):
                align_face(frame, invalid)
