import importlib.util
from pathlib import Path
import tempfile
import unittest

from face_database import FaceDatabase, DIMENSIONS
from face_notifications import configuration


class ConfigurationTests(unittest.TestCase):
    def test_native_notification_switches_ids_and_threshold_are_strict(self):
        self.assertEqual(configuration({"alert_limit": 3})["alert_limit"], "3")
        self.assertEqual(configuration({"face_id": [2, 1, 2]})["face_id"], [1, 2])
        for change in ({"alert_limit": True}, {"alert_limit": 21}, {"alert_limit": 0},
                       {"msg_push_enabled": True}, {"face_id": [True]}, {"face_id": [-1]},
                       {"unknown": "on"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                configuration(change)


@unittest.skipUnless(importlib.util.find_spec("duckdb"), "Optional DuckDB dependency not installed")
class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.path = Path(self.work.name)/"faces"/"test.duckdb"
        self.db = FaceDatabase(self.path)
        self.addCleanup(lambda: self.db.close())
        self.mac = "10:00:00:00:00:02"
        self.now = 1794341500
        self.key = "event-" + "f" * 24
        self.face = self.db.add("Private reference", "familiar", b"\xff\xd8test\xff\xd9", [1.0]+[0.0]*(DIMENSIONS-1))
        self.db.link(self.face, self.key, self.now)

    def enable_test_rule(self, ids=None):
        # Test fixture only: production API cannot enable without verified delivery.
        self.db.save_notification_config(self.mac, {"msg_push_enabled": "on", "familiar_enable": "on",
            "face_id": [self.face] if ids is None else ids})

    def queued(self):
        return self.db.connection.execute("SELECT message_type,state,attempts FROM face_notification_outbox").fetchall()

    def test_selected_familiar_is_queued_once_and_persists_without_claiming_sent(self):
        self.enable_test_rule()
        self.assertTrue(self.db.queue_familiar_notification(self.mac,self.face,self.key,self.now,now=self.now))
        self.assertFalse(self.db.queue_familiar_notification(self.mac,self.face,self.key,self.now,now=self.now))
        self.db.close();self.db=FaceDatabase(self.path)
        self.assertEqual(self.queued(), [("familiarFaceDetected", "awaiting_verified_transport", 0)])
        self.assertEqual(self.db.notification_config(self.mac)["face_id"], [self.face])

    def test_disabled_unselected_stale_or_unlinked_events_never_enter_queue(self):
        self.assertFalse(self.db.queue_familiar_notification(self.mac,self.face,self.key,self.now,now=self.now))
        self.enable_test_rule([])
        self.assertFalse(self.db.queue_familiar_notification(self.mac,self.face,self.key,self.now,now=self.now))
        self.enable_test_rule()
        self.assertFalse(self.db.queue_familiar_notification(self.mac,self.face,self.key,self.now,now=self.now+301))
        self.assertFalse(self.db.queue_familiar_notification(self.mac,self.face,"event-"+"a"*24,self.now,now=self.now))
        self.assertEqual(self.queued(), [])

    def test_profile_and_recording_removal_cancel_queued_alerts(self):
        self.enable_test_rule()
        self.db.queue_familiar_notification(self.mac,self.face,self.key,self.now,now=self.now)
        self.db.prune_events(set())
        self.assertEqual(self.queued(), [])
        self.db.link(self.face,self.key,self.now)
        self.db.queue_familiar_notification(self.mac,self.face,self.key,self.now,now=self.now)
        self.db.delete(self.face)
        self.assertEqual(self.queued(), [])
        self.assertEqual(self.db.notification_config(self.mac)["face_id"], [])

    def test_merge_moves_selected_profile_and_cancels_source_alert(self):
        self.enable_test_rule()
        self.db.queue_familiar_notification(self.mac, self.face, self.key, self.now, now=self.now)
        target = self.db.add("", "familiar", b"\xff\xd8test\xff\xd9", [0.0, 1.0]+[0.0]*(DIMENSIONS-2))
        self.db.merge(self.face, target)
        self.assertEqual(self.queued(), [])
        self.assertEqual(self.db.notification_config(self.mac)["face_id"], [target])
        self.assertTrue(self.db.queue_familiar_notification(self.mac, target, self.key, self.now, now=self.now))
