import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import recording_observation as observation


class ObservationTests(unittest.TestCase):
    def test_observation_survives_restarts_counts_new_files_and_stops_after_24_hours(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            store = root / "recordings"
            (store / "events").mkdir(parents=True)
            (store / "failed-uploads").mkdir()
            (root / "enrolled.json").write_text(json.dumps({"private-mac": {"device_model": "TD21",
                "hub_storage_enabled": True, "recording_mode": "persistent_native", "bind_code": "private-token"}}))
            state_file = root / "observation.json"
            with patch("recording_observation.STORE", store), patch("recording_observation.STATE", state_file), \
                    patch("recording_observation.check_store"), patch("recording_observation.free_bytes", return_value=9000):
                first = observation.sample(now=100)
                self.assertEqual(first["samples"][-1]["new_completed_videos"], 0)
                media = store / "events/event-new.mp4"
                media.write_bytes(b"media")
                media.with_suffix(".mp4.json").write_text(json.dumps({"validated_recording": True,
                    "format_version": 1, "bytes": 5, "password_hash": "private-hash"}))
                (store / "failed-uploads/new.wire.json").write_text('{"nonce":"private-nonce"}')
                second = observation.sample(now=200)
                self.assertEqual(second["started_at"], first["started_at"])
                self.assertEqual(second["samples"][-1]["new_completed_videos"], 1)
                self.assertEqual(second["samples"][-1]["new_retained_failed_events"], 1)
                finished = observation.sample(now=86_500)
                self.assertTrue(finished["complete"])
                self.assertEqual(observation.sample(now=90_000), finished)
                for secret in ("private-token", "private-hash", "private-nonce", "private-mac"):
                    self.assertNotIn(secret, state_file.read_text())
                self.assertEqual(state_file.stat().st_mode & 0o777, 0o600)
