import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import recording_retention as retention


class RetentionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Path(directory.name)
        (self.store / "events").mkdir()
        self.mac = "10:00:00:00:00:02"
        for name, kwargs in (("STORE", {"new": self.store}), ("os.path.ismount", {"return_value": True}),
                             ("disk_info", {"return_value": {"status": "normal"}}),
                             ("LOW_FREE", {"new": 1000}), ("TARGET_FREE", {"new": 2000})):
            item = patch("recording_retention." + name, **kwargs)
            item.start()
            self.addCleanup(item.stop)
        self.free = patch("recording_retention.free_bytes", return_value=500)
        self.free.start()
        self.addCleanup(self.free.stop)

    def event(self, event_id, age=600, kind="mp4"):
        stem = "event-" + hashlib.sha256((self.mac + ":" + event_id).encode()).hexdigest()[:24]
        path = self.store / "events" / (stem + "." + kind)
        path.write_bytes(b"saved media")
        index = path.with_suffix(path.suffix + ".json")
        index.write_text(json.dumps({"camera_mac": self.mac, "event_id": event_id, "format_version": 1,
            "format": kind, "bytes": path.stat().st_size, "validated_recording": kind == "mp4",
            "verified_tracks": [{"codec_type": "video"}]}))
        for item in (path, index):
            os.utime(item, (time.time()-age, time.time()-age))
        return path

    def test_cleanup_deletes_oldest_group_only_until_target_and_preserves_other_directories(self):
        oldest = self.event("1", age=1000)
        thumbnail = self.event("1", age=1000, kind="jpg")
        newest = self.event("2", age=600)
        capture = self.store / "native-captures"
        capture.mkdir()
        frozen = capture / "original.wire"
        frozen.write_bytes(b"private evidence")
        photo = self.store / "events" / "unindexed-photo.jpg"
        photo.write_bytes(b"unrelated")
        with patch("recording_retention.free_bytes", side_effect=lambda: 500 if oldest.exists() else 2500):
            result = retention.cleanup()
        self.assertEqual(result["deleted_events"], 1)
        self.assertFalse(oldest.exists())
        self.assertFalse(thumbnail.exists())
        self.assertTrue(newest.exists())
        self.assertTrue(frozen.exists())
        self.assertTrue(photo.exists())

    def test_upload_playback_or_thumbnail_lease_prevents_all_deletion(self):
        path = self.event("1")
        with retention.activity():
            result = retention.cleanup()
        self.assertEqual(result["status"], "busy")
        self.assertTrue(path.exists())
        self.assertEqual(retention.cleanup()["deleted_events"], 1)

    def test_recent_or_partial_or_unvalidated_groups_are_never_deleted(self):
        recent = self.event("1", age=10)
        incomplete = self.event("2")
        incomplete.with_suffix(".mp4.json").unlink()
        invalid = self.event("3")
        index = invalid.with_suffix(".mp4.json")
        data = json.loads(index.read_text())
        data["validated_recording"] = False
        index.write_text(json.dumps(data))
        self.assertEqual(retention.cleanup()["deleted_events"], 0)
        self.assertTrue(all(path.exists() for path in (recent, incomplete, invalid)))

    def test_missing_mount_or_symlinked_events_cannot_touch_an_external_file(self):
        path = self.event("1")
        with patch("recording_retention.os.path.ismount", return_value=False):
            self.assertEqual(retention.cleanup()["status"], "unavailable")
        self.assertTrue(path.exists())
        external = self.store / "external"
        external.mkdir()
        saved = self.store / "saved-events"
        (self.store / "events").rename(saved)
        (self.store / "events").symlink_to(external, target_is_directory=True)
        protected = external / path.name
        protected.write_bytes(b"important photo")
        self.assertEqual(retention.cleanup()["status"], "unavailable")
        self.assertEqual(protected.read_bytes(), b"important photo")

    def test_symlinked_media_and_noncanonical_indices_are_preserved(self):
        path = self.event("1")
        outside = self.store / "photo.jpg"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        other = self.event("2")
        index = other.with_suffix(".mp4.json")
        data = json.loads(index.read_text())
        data["event_id"] = "999"
        index.write_text(json.dumps(data))
        self.assertEqual(retention.cleanup()["deleted_events"], 0)
        self.assertTrue(path.is_symlink())
        self.assertTrue(other.exists())

    def test_dry_run_and_adequate_free_space_do_not_delete_files(self):
        path = self.event("1")
        result = retention.cleanup(dry_run=True)
        self.assertEqual(result["planned_events"], 1)
        self.assertEqual(result["deleted_events"], 0)
        self.assertTrue(path.exists())
        with patch("recording_retention.free_bytes", return_value=3000):
            self.assertEqual(retention.cleanup()["planned_events"], 0)
        self.assertTrue(path.exists())
