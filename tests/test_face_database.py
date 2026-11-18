import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from face_database import FaceDatabase, vector, DIMENSIONS, CURRENT_MODEL, LEGACY_MODEL


@unittest.skipUnless(importlib.util.find_spec("duckdb"), "Optional DuckDB dependency not installed")
class FaceDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.path = Path(self.work.name) / "private" / "faces.duckdb"
        self.db = FaceDatabase(self.path)
        self.addCleanup(lambda: self.db.close())
        self.image = b"\xff\xd8owned-test\xff\xd9"
        self.embedding = [1.0] + [0.0] * (DIMENSIONS - 1)

    def add(self, name="Owned test", embedding=None):
        return self.db.add(name, "familiar", self.image, self.embedding if embedding is None else embedding,
                           verified=True)

    def test_profiles_settings_photos_and_embeddings_persist_privately(self):
        face = self.add()
        self.db.set_enabled(True)
        self.db.close()
        self.db = FaceDatabase(self.path)
        self.assertTrue(self.db.enabled)
        self.assertEqual(self.db.photo(face), self.image)
        self.assertEqual(self.db.match(self.embedding), face)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("embedding", self.db.search()[0])
        self.assertNotIn("image", self.db.search()[0])

    def test_continuous_history_past_ten_thousand_clips_keeps_processing(self):
        face = self.add()
        self.db.connection.execute("""INSERT INTO appearances
            SELECT ?, 'event-' || lpad(lower(to_hex(i)),24,'0'), 1794341500 FROM range(10001) AS clips(i)""", [face])
        key = 'event-' + 'f'*24
        self.db.link(face, key, 1794341500)
        keys = {'event-' + format(i, '024x') for i in range(10001)} | {key}
        self.assertEqual(self.db.prune_events(keys), 0)
        self.db.mark_analyzed(key)
        self.assertEqual(self.db.unanalyzed(keys), keys - {key})
        self.assertEqual(len(self.db.events(face)), 10002)
        self.assertEqual(self.db.unanalyzed(set()), set())

    def test_analysis_revision_reprocesses_old_clips_without_resetting_profiles(self):
        face = self.add()
        event = "event-"+"f"*24
        self.db.link(face, event, 1794341500)
        self.db.mark_analyzed(event)
        self.assertTrue(self.db.analyzed(event))
        self.db.connection.execute("UPDATE analyzed_events SET analysis_version='' WHERE event_key=?", [event])
        self.assertFalse(self.db.analyzed(event))
        self.assertEqual(self.db.photo(face), self.image)
        self.assertEqual(len(self.db.events(face)), 1)
        self.db.mark_analyzed(event)
        self.assertTrue(self.db.analyzed(event))

    def test_rename_delete_and_event_retention_have_separate_lifetimes(self):
        face = self.add()
        key = "event-" + "a" * 24
        self.db.link(face, key, 1794341500)
        self.db.link(face, key, 1794341500)
        self.assertEqual(len(self.db.events(face)), 1)
        self.db.change(face, name="Renamed", tag="stranger")
        self.assertEqual(self.db.search(tags=["stranger"])[0]["name"], "Renamed")
        self.assertEqual(self.db.prune_events(set()), 1)
        self.assertEqual(len(self.db.search()), 1)
        self.db.link(face, key, 1794341500)
        self.db.delete(face)
        self.assertEqual(self.db.events(face), [])
        self.assertEqual(self.db.search(), [])
        self.assertIsNone(self.db.match(self.embedding))
        with self.assertRaises(ValueError):
            self.db.photo(face)

    def test_matching_rejects_unknown_and_ambiguous_faces(self):
        first = self.add()
        self.assertIsNone(self.db.match([0.0, 1.0] + [0.0] * (DIMENSIONS - 2)))
        self.assertEqual(self.db.match(self.embedding), first)
        self.add("Ambiguous reference")
        self.assertIsNone(self.db.match(self.embedding))

    def test_invalid_inputs_roll_back_without_interpreting_sql_or_paths(self):
        face = self.add("Robert'); DROP TABLE faces; --")
        for value in ([], [0.0] * DIMENSIONS, [float("nan")] * DIMENSIONS, [True] * DIMENSIONS):
            with self.assertRaises(ValueError):
                self.db.add("bad", "familiar", self.image, value)
        with self.assertRaises(ValueError):
            self.db.change(face, tag="invalid")
        self.assertEqual(len(self.db.search()), 1)
        with self.assertRaises(ValueError):
            self.db.link(face, "../../private", 123)
        with self.assertRaises(ValueError):
            self.db.set_enabled("on")
        with self.assertRaises(ValueError):
            self.db.photo(True)

    def test_concurrent_api_and_worker_writes_share_one_connection_safely(self):
        errors = []
        def write(number):
            try:
                for item in range(4):
                    face = self.add(f"{number}/{item}")
                    self.db.change(face, name="Edited")
                    self.db.search()
            except Exception as error:
                errors.append(type(error).__name__)
        threads = [threading.Thread(target=write, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(self.db.search()), 16)

    def test_biometric_database_never_loads_external_files_or_extensions(self):
        with self.assertRaises(Exception):
            self.db.connection.execute("SELECT * FROM read_text('/etc/passwd')")
        with self.assertRaises(ValueError):
            self.db.search(tags=["familiar') OR 1=1 --"])

    def test_legacy_embedding_migration_preserves_profiles_and_never_compares_models(self):
        face = self.db.connection.execute("""INSERT INTO faces(name,tag,image,embedding,created,fresh,modified,verified,embedding_model)
            VALUES (?,?,?,?,?,?,?,?,?) RETURNING id""", ["Preserve enrolled reference", "familiar", self.image,
            [1.0] + [0.0] * 127, 1, 1, 1, True, LEGACY_MODEL]).fetchone()[0]
        event = "event-" + "e" * 24
        self.db.link(face, event, 1794341500)
        self.db.mark_analyzed(event)
        self.db.connection.execute("ALTER TABLE faces ALTER COLUMN embedding TYPE FLOAT[128]")
        self.db.connection.execute("UPDATE analyzed_events SET embedding_model=?", [LEGACY_MODEL])
        self.db.close()
        self.db = FaceDatabase(self.path)
        self.assertEqual(self.db.photo(face), self.image)
        self.assertEqual(self.db.search()[0]["name"], "Preserve enrolled reference")
        self.assertEqual(self.db.pending_embeddings(), [(face, self.image)])
        self.assertIsNone(self.db.match(self.embedding))
        self.assertFalse(self.db.analyzed(event))
        self.assertEqual(len(self.db.events(face)), 1)
        self.db.replace_embedding(face, self.embedding)
        self.assertEqual(self.db.match(self.embedding), face)
        self.assertEqual(self.db.pending_embeddings(), [])
        self.db.mark_analyzed(event)
        self.assertTrue(self.db.analyzed(event))

    def test_migration_and_restart_survive_unclean_process_exit_without_losing_writes(self):
        self.db.connection.execute("ALTER TABLE faces ALTER COLUMN embedding TYPE FLOAT[128]")
        self.db.close()
        script = """
import os, sys
from face_database import FaceDatabase, DIMENSIONS
db = FaceDatabase(sys.argv[1])
db.set_enabled(True)
db.add('Synthetic crash reference', 'familiar', b'\\xff\\xd8test\\xff\\xd9', [1.0]+[0.0]*(DIMENSIONS-1))
os._exit(0)
"""
        for count in (1, 2):
            subprocess.run([sys.executable, "-c", script, str(self.path)], check=True, timeout=15)
            self.db = FaceDatabase(self.path)
            self.assertTrue(self.db.enabled)
            self.assertEqual(len(self.db.search()), count)
            self.assertIsNotNone(self.db.match(self.embedding, margin=0))
            self.db.close()


class EmbeddingTests(unittest.TestCase):
    def test_embedding_normalization_and_nonfinite_rejection(self):
        self.assertEqual(vector([2] + [0] * (DIMENSIONS - 1)), [1] + [0] * (DIMENSIONS - 1))
        for value in ([float("inf")] * DIMENSIONS, [1e308] * DIMENSIONS, [False] * DIMENSIONS):
            with self.assertRaises(ValueError):
                vector(value)
