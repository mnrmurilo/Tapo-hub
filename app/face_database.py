"""Private DuckDB face profiles and event links; one owning process, serialized access."""
from contextlib import contextmanager
import math
import os
from pathlib import Path
import threading
import time

DIMENSIONS = 512
from settings import CONFIG
CURRENT_MODEL = CONFIG.get('face_model_id', 'arcface-buffalo-sc-w600k_mbf-v1')
CURRENT_ANALYSIS = "original-1280-dense-unknown-quality-v2"
LEGACY_MODEL = "opencv-sface-2021dec-v1"
MAX_IMAGE = 48_000
MAX_PROFILES = 300
MAX_FACES = MAX_PROFILES * 2


class FaceCapacityError(ValueError):
    pass


def vector(values):
    if not isinstance(values, (list, tuple)) or len(values) != DIMENSIONS:
        raise ValueError("Invalid face embedding")
    if any(type(x) not in (int, float) or not math.isfinite(x) for x in values):
        raise ValueError("Invalid face embedding")
    norm = math.sqrt(sum(x * x for x in values))
    if not math.isfinite(norm) or norm < 1e-12:
        raise ValueError("Invalid face embedding")
    return [x / norm for x in values]


def profile_fields(name, tag):
    if (not isinstance(name, str) or len(name) > 64 or any(ord(c) < 32 for c in name)
            or tag not in ("familiar", "stranger")):
        raise ValueError("Invalid face profile")
    return name, tag


class FaceDatabase:
    def __init__(self, path):
        import duckdb
        self.path = Path(path)
        if self.path.parent.is_symlink() or self.path.is_symlink() or Path(str(path) + ".wal").is_symlink():
            raise ValueError("Unsafe face database path")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self.lock = threading.RLock()
        self.connection = duckdb.connect(str(self.path), config={
            "threads": "1", "memory_limit": "32MB", "enable_external_access": "false",
            "autoload_known_extensions": "false", "autoinstall_known_extensions": "false",
            "temp_directory": ""})
        self.connection.execute("CREATE SEQUENCE IF NOT EXISTS face_ids START 1")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS faces (
            id BIGINT PRIMARY KEY DEFAULT nextval('face_ids'), name VARCHAR NOT NULL,
            tag VARCHAR NOT NULL, image BLOB NOT NULL, embedding FLOAT[] NOT NULL,
            created BIGINT NOT NULL, fresh BIGINT NOT NULL, modified BIGINT NOT NULL,
            verified BOOLEAN NOT NULL)""")
        # Keep old profiles and IDs; only compare embeddings produced by the same model.
        self.connection.execute("ALTER TABLE faces ADD COLUMN IF NOT EXISTS embedding_model VARCHAR DEFAULT 'opencv-sface-2021dec-v1'")
        embedding_type = next(row[2] for row in self.connection.execute("PRAGMA table_info('faces')").fetchall()
                              if row[1] == "embedding")
        if embedding_type != "FLOAT[]":
            self.connection.execute("ALTER TABLE faces ALTER COLUMN embedding TYPE FLOAT[]")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS appearances (
            face_id BIGINT NOT NULL, event_key VARCHAR NOT NULL, event_start BIGINT NOT NULL,
            PRIMARY KEY(face_id, event_key))""")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY, enabled BOOLEAN NOT NULL)""")
        self.connection.execute("INSERT INTO settings VALUES (1, false) ON CONFLICT DO NOTHING")
        self.connection.execute("CREATE TABLE IF NOT EXISTS analyzed_events (event_key VARCHAR PRIMARY KEY)")
        self.connection.execute("ALTER TABLE analyzed_events ADD COLUMN IF NOT EXISTS embedding_model VARCHAR DEFAULT 'opencv-sface-2021dec-v1'")
        self.connection.execute("ALTER TABLE analyzed_events ADD COLUMN IF NOT EXISTS analysis_version VARCHAR DEFAULT ''")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS face_notification_settings (
            camera_mac VARCHAR PRIMARY KEY, master BOOLEAN NOT NULL, familiar BOOLEAN NOT NULL,
            stranger BOOLEAN NOT NULL, alert_limit INTEGER NOT NULL, face_ids BIGINT[] NOT NULL)""")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS face_notification_outbox (
            notification_id VARCHAR PRIMARY KEY, camera_mac VARCHAR NOT NULL, face_id BIGINT NOT NULL,
            event_key VARCHAR NOT NULL, event_time BIGINT NOT NULL, message_type VARCHAR NOT NULL,
            state VARCHAR NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt BIGINT NOT NULL, expires_at BIGINT NOT NULL)""")
        # DuckDB 1.5.6 cannot replay some ALTER TYPE WAL entries after an unclean exit.
        self.connection.execute("CHECKPOINT")
        self._private()

    def _private(self):
        for path in (self.path, Path(str(self.path) + ".wal")):
            if path.exists():
                os.chmod(path, 0o600)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.connection.execute("BEGIN TRANSACTION")
            try:
                yield self.connection
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            finally:
                self._private()

    def close(self):
        with self.lock:
            self.connection.close()
            self._private()

    @property
    def enabled(self):
        with self.lock:
            return self.connection.execute("SELECT enabled FROM settings WHERE id=1").fetchone()[0]

    def set_enabled(self, value):
        if type(value) is not bool:
            raise ValueError("Invalid face setting")
        with self.transaction() as db:
            db.execute("UPDATE settings SET enabled=? WHERE id=1", [value])

    def add(self, name, tag, image, embedding, *, verified=False):
        profile_fields(name, tag)
        embedding = vector(embedding)
        if (not isinstance(image, bytes) or not 4 <= len(image) <= MAX_IMAGE
                or not image.startswith(b"\xff\xd8") or not image.endswith(b"\xff\xd9")):
            raise ValueError("Invalid face image")
        now = int(time.time() * 1000)
        with self.transaction() as db:
            if db.execute("SELECT count(*) FROM faces WHERE tag=?", [tag]).fetchone()[0] >= MAX_PROFILES:
                raise FaceCapacityError("Face capacity reached")
            return db.execute("""INSERT INTO faces(name,tag,image,embedding,created,fresh,modified,verified,embedding_model)
                VALUES (?,?,?,?,?,?,?,?,?) RETURNING id""",
                [name, tag, image, embedding, now, now, now, bool(verified), CURRENT_MODEL]).fetchone()[0]

    def search(self, *, tags=None, ids=None, updated_after=0, limit=100):
        if (type(updated_after) is not int or updated_after < 0 or type(limit) is not int
                or not 1 <= limit <= MAX_FACES):
            raise ValueError("Invalid face search")
        if tags is not None and (not isinstance(tags, list) or any(t not in ("familiar", "stranger") for t in tags)):
            raise ValueError("Invalid face tags")
        if ids is not None and (not isinstance(ids, list) or len(ids) > MAX_FACES
                                or any(type(i) is not int or i <= 0 for i in ids)):
            raise ValueError("Invalid face IDs")
        with self.lock:
            rows = self.connection.execute("""SELECT id,name,tag,created,fresh,modified,verified,
                (SELECT max(event_start) FROM appearances WHERE face_id=faces.id)
                FROM faces WHERE modified>=? ORDER BY fresh DESC,id""", [updated_after]).fetchall()
        # Native display times are Unix seconds; the opaque update cursor stays milliseconds.
        return [{"face_id": r[0], "name": r[1], "tag": r[2], "create_time": r[3] // 1000,
                 "fresh_time": r[7] if r[7] is not None else r[4] // 1000,
                 "modify_time": r[5], "user_verified": r[6]}
                for r in rows if (not tags or r[2] in tags) and (not ids or r[0] in ids)][:limit]

    def photo(self, face_id):
        if type(face_id) is not int or face_id <= 0:
            raise ValueError("Invalid face ID")
        with self.lock:
            row = self.connection.execute("SELECT image FROM faces WHERE id=?", [face_id]).fetchone()
        if row is None:
            raise ValueError("Face not found")
        return bytes(row[0])

    def change(self, face_id, *, name=None, tag=None):
        self.apply_commands([{"operate": "set", "ori_face_id": face_id,
                              "cover": {"name": name, "tag": tag}}])

    def delete(self, face_id):
        self.apply_commands([{"operate": "del", "ori_face_id": face_id}])
        # Logical deletion removes API access; physical erasure from old backups is separate.

    def merge(self, source, target):
        if any(type(i) is not int or i <= 0 for i in (source, target)) or source == target:
            raise ValueError("Invalid face merge")
        self.apply_commands([{"operate": "set", "ori_face_id": source, "cover": {"face_id": target}}])

    def apply_commands(self, commands):
        if not isinstance(commands, list) or not 1 <= len(commands) <= MAX_PROFILES:
            raise ValueError("Invalid face operation batch")
        # A native combine is a batch: any rejected edit must roll back every earlier edit.
        with self.transaction() as db:
            for query in commands:
                if not isinstance(query, dict) or query.get("operate") not in ("del", "set", "verify"):
                    raise ValueError("Unsupported face operation")
                source = query.get("ori_face_id")
                if type(source) is not int or not 0 < source < 2**63:
                    raise ValueError("Invalid face ID")
                deleting = query["operate"] == "del"
                cover = {} if deleting else query.get("cover")
                if not isinstance(cover, dict):
                    raise ValueError("Invalid face cover")
                target = source if cover.get("face_id") is None else cover["face_id"]
                if type(target) is not int or not 0 < target < 2**63:
                    raise ValueError("Invalid target face ID")
                if not deleting:
                    if db.execute("SELECT count(*) FROM faces WHERE id IN (?,?)", [source, target]).fetchone()[0] != (1 if source == target else 2):
                        raise ValueError("Face not found")
                    row = db.execute("SELECT name,tag FROM faces WHERE id=?", [target]).fetchone()
                    name, tag = profile_fields(row[0] if cover.get("name") is None else cover["name"],
                                               row[1] if cover.get("tag") is None else cover["tag"])
                    if tag != row[1] and db.execute("SELECT count(*) FROM faces WHERE tag=?", [tag]).fetchone()[0] >= MAX_PROFILES:
                        raise FaceCapacityError("Face capacity reached")
                    if source != target:
                        db.execute("""INSERT INTO appearances SELECT ?,event_key,event_start FROM appearances
                                      WHERE face_id=? ON CONFLICT DO NOTHING""", [target, source])
                    db.execute("UPDATE faces SET name=?,tag=?,modified=?,verified=true WHERE id=?",
                               [name, tag, int(time.time() * 1000), target])
                if deleting or source != target:
                    db.execute("DELETE FROM appearances WHERE face_id=?", [source])
                    db.execute("DELETE FROM face_notification_outbox WHERE face_id=?", [source])
                    db.execute("DELETE FROM faces WHERE id=?", [source])
                    for mac, ids in db.execute("SELECT camera_mac,face_ids FROM face_notification_settings").fetchall():
                        if source in ids:
                            ids = sorted({target if key == source else key for key in ids
                                          if not deleting or key != source})
                            db.execute("UPDATE face_notification_settings SET face_ids=? WHERE camera_mac=?", [ids, mac])

    def match(self, embedding, *, threshold=0.55, margin=0.06, tags=("familiar", "stranger")):
        probe = vector(embedding)
        if not 0 < threshold <= 1 or not 0 <= margin <= 1:
            raise ValueError("Invalid face threshold")
        if not isinstance(tags, (list, tuple)) or not tags or any(tag not in ("familiar", "stranger") for tag in tags):
            raise ValueError("Invalid face matching tags")
        with self.lock:
            rows = self.connection.execute("SELECT id,embedding FROM faces WHERE embedding_model=? AND tag IN (SELECT unnest(?)) ORDER BY id",
                                           [CURRENT_MODEL, list(tags)]).fetchall()
        ranked = sorted(((sum(a * b for a, b in zip(probe, row[1])), row[0]) for row in rows), reverse=True)
        if not ranked or ranked[0][0] < threshold:
            return None
        if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < margin:
            return None
        return ranked[0][1]

    def link(self, face_id, event_key, event_start):
        import re
        if (type(face_id) is not int or face_id <= 0 or not isinstance(event_key, str)
                or not re.fullmatch(r"event-[0-9a-f]{24}", event_key)
                or type(event_start) is not int or not 0 < event_start <= 4_102_444_800):
            raise ValueError("Invalid face event link")
        with self.transaction() as db:
            if not db.execute("SELECT id FROM faces WHERE id=?", [face_id]).fetchone():
                raise ValueError("Face not found")
            # Appearance history is bounded by retained recordings, including continuous clips.
            db.execute("INSERT INTO appearances VALUES (?,?,?) ON CONFLICT DO NOTHING", [face_id, event_key, event_start])
            db.execute("UPDATE faces SET fresh=?,modified=? WHERE id=?",
                       [int(time.time() * 1000), int(time.time() * 1000), face_id])

    def events(self, face_id):
        if type(face_id) is not int or face_id <= 0:
            raise ValueError("Invalid face ID")
        with self.lock:
            return self.connection.execute("SELECT event_key,event_start FROM appearances WHERE face_id=? ORDER BY event_start",
                                           [face_id]).fetchall()

    def prune_events(self, valid_keys):
        import re
        if (not isinstance(valid_keys, set) or any(not isinstance(key, str)
                or not re.fullmatch(r"event-[0-9a-f]{24}", key) for key in valid_keys)):
            raise ValueError("Invalid retained events")
        with self.transaction() as db:
            expired = [row[0] for row in db.execute("SELECT DISTINCT event_key FROM appearances").fetchall()
                       if row[0] not in valid_keys]
            for key in expired:
                db.execute("DELETE FROM appearances WHERE event_key=?", [key])
                db.execute("DELETE FROM face_notification_outbox WHERE event_key=?", [key])
            for (key,) in db.execute("SELECT event_key FROM analyzed_events").fetchall():
                if key not in valid_keys:
                    db.execute("DELETE FROM analyzed_events WHERE event_key=?", [key])
        return len(expired)

    def analyzed(self, key):
        with self.lock:
            return bool(self.connection.execute("SELECT 1 FROM analyzed_events WHERE event_key=? AND embedding_model=? AND analysis_version=?",
                                                [key, CURRENT_MODEL, CURRENT_ANALYSIS]).fetchone())

    def unanalyzed(self, keys):
        """Batch the backlog lookup so continuous recording does not add one query per clip."""
        with self.lock:
            return {row[0] for row in self.connection.execute("""
                SELECT retained.event_key FROM unnest(?) AS retained(event_key)
                WHERE NOT EXISTS (SELECT 1 FROM analyzed_events AS analyzed
                    WHERE analyzed.event_key=retained.event_key AND embedding_model=? AND analysis_version=?)
                """, [list(keys), CURRENT_MODEL, CURRENT_ANALYSIS]).fetchall()}

    def recording_keys(self):
        with self.lock:
            return {row[0] for row in self.connection.execute(
                "SELECT event_key FROM analyzed_events UNION SELECT event_key FROM appearances").fetchall()}

    def event_face_counts(self, key):
        with self.lock:
            row = self.connection.execute("""SELECT count(DISTINCT face_id),
                count(DISTINCT CASE WHEN tag='familiar' THEN face_id END),
                count(DISTINCT CASE WHEN tag='stranger' THEN face_id END)
                FROM appearances JOIN faces ON faces.id=appearances.face_id WHERE event_key=?""", [key]).fetchone()
        return dict(zip(('face_count', 'familiar_count', 'stranger_count'), row))

    def mark_analyzed(self, key):
        with self.transaction() as db:
            db.execute("INSERT INTO analyzed_events (event_key,embedding_model,analysis_version) VALUES (?,?,?) ON CONFLICT(event_key) DO UPDATE SET embedding_model=excluded.embedding_model,analysis_version=excluded.analysis_version",
                       [key, CURRENT_MODEL, CURRENT_ANALYSIS])

    def counters(self):
        with self.lock:
            return {name: self.connection.execute("SELECT count(*) FROM " + name).fetchone()[0]
                    for name in ("faces", "appearances", "analyzed_events")}

    def pending_embeddings(self):
        with self.lock:
            return [(row[0], bytes(row[1])) for row in self.connection.execute(
                "SELECT id,image FROM faces WHERE embedding_model<>? ORDER BY id LIMIT 5", [CURRENT_MODEL]).fetchall()]

    def replace_embedding(self, face_id, embedding):
        embedding = vector(embedding)
        with self.transaction() as db:
            db.execute("UPDATE faces SET embedding=?,embedding_model=? WHERE id=?", [embedding, CURRENT_MODEL, face_id])

    def notification_config(self, camera_mac):
        from camera_registry import normalize_mac
        from face_notifications import configuration
        camera_mac = normalize_mac(camera_mac)
        with self.lock:
            row = self.connection.execute("SELECT master,familiar,stranger,alert_limit,face_ids FROM face_notification_settings WHERE camera_mac=?",
                                          [camera_mac]).fetchone()
        if row is None:
            return configuration({})
        return configuration({"msg_push_enabled": "on" if row[0] else "off",
            "familiar_enable": "on" if row[1] else "off", "stranger_enable": "on" if row[2] else "off",
            "alert_limit": row[3], "face_id": list(row[4])})

    def save_notification_config(self, camera_mac, changes):
        from camera_registry import normalize_mac
        from face_notifications import configuration
        camera_mac = normalize_mac(camera_mac)
        with self.lock:
            config = configuration(changes, self.notification_config(camera_mac))
            with self.transaction() as db:
                db.execute("""INSERT INTO face_notification_settings VALUES (?,?,?,?,?,?)
                    ON CONFLICT(camera_mac) DO UPDATE SET master=excluded.master,familiar=excluded.familiar,
                    stranger=excluded.stranger,alert_limit=excluded.alert_limit,face_ids=excluded.face_ids""",
                    [camera_mac, config["msg_push_enabled"] == "on", config["familiar_enable"] == "on",
                     config["stranger_enable"] == "on", int(config["alert_limit"]), config["face_id"]])
        return config

    def queue_familiar_notification(self, camera_mac, face_id, event_key, event_time, *, now=None):
        """Queue selected familiar events; delivery/unknown threshold semantics remain gated."""
        import hashlib
        from camera_registry import normalize_mac
        from face_notifications import MESSAGE_TYPES
        camera_mac = normalize_mac(camera_mac)
        now = int(time.time()) if now is None else now
        if type(face_id) is not int or face_id <= 0:
            raise ValueError("Invalid notification face ID")
        if type(event_time) is not int or not 0 < event_time <= 4_102_444_800:
            raise ValueError("Invalid notification time")
        if event_time < now - 300 or event_time > now + 30:
            return False
        with self.lock:
            config = self.notification_config(camera_mac)
            if (config["msg_push_enabled"] != "on" or config["familiar_enable"] != "on"
                    or face_id not in config["face_id"]):
                return False
            with self.transaction() as db:
                row = db.execute("""SELECT 1 FROM appearances JOIN faces ON faces.id=appearances.face_id
                    WHERE face_id=? AND event_key=? AND event_start=? AND tag='familiar'""",
                    [face_id, event_key, event_time]).fetchone()
                if row is None:
                    return False
                db.execute("DELETE FROM face_notification_outbox WHERE expires_at<?", [now])
                key = hashlib.sha256(f"{camera_mac}:{face_id}:{event_key}:familiar".encode()).hexdigest()
                if db.execute("SELECT 1 FROM face_notification_outbox WHERE notification_id=?", [key]).fetchone():
                    return False
                if db.execute("SELECT count(*) FROM face_notification_outbox").fetchone()[0] >= 1000:
                    raise ValueError("Notification queue capacity reached")
                db.execute("""INSERT INTO face_notification_outbox
                    (notification_id,camera_mac,face_id,event_key,event_time,message_type,state,next_attempt,expires_at)
                    VALUES (?,?,?,?,?,?,'awaiting_verified_transport',?,?)""",
                    [key, camera_mac, face_id, event_key, event_time, MESSAGE_TYPES["familiar"], now, event_time+300])
        return True
