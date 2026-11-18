import io
import hashlib
import json
import threading
import tempfile
from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.request import parse_http_list, parse_keqv_list

from camera_media import digest, decrypt_media, headers
from playback_media import MediaAuth, serve_playback, BOUNDARY, encrypt, routed_query
from recording_playback import RecordingPlayback


class PlaybackMediaTests(unittest.TestCase):
    def test_stream_uri_routes_selector_free_download_to_the_correct_camera(self):
        storage = SimpleNamespace(lock=threading.RLock(), devices={
            '10:00:00:00:00:02': {'device_model': 'TD21', 'device_id': 'owned-td21', 'hub_storage_enabled': True},
            '10:00:00:00:00:04': {'device_model': 'C400', 'hardware_version': '2.0', 'device_id': 'owned-c400', 'hub_storage_enabled': True}})
        player = RecordingPlayback(storage)
        handler = SimpleNamespace(path='/stream?deviceId=owned-c400&playerId=client', server=SimpleNamespace(playback=player))
        with self.assertLogs('tapo-hub-lab', level='INFO') as logs:
            query = routed_query(handler, {'start_time': '100', 'media_type': 2})
        self.assertIn('camera_id', '\n'.join(logs.output))
        self.assertNotIn('owned-c400', '\n'.join(logs.output))
        self.assertEqual(player.camera(query), '10:00:00:00:00:04')
        with self.assertRaises(ValueError):
            player.camera(routed_query(handler, {'camera_mac': '10:00:00:00:00:02'}))
        with self.assertRaises(ValueError):
            routed_query(handler, {'child_device_id': 'owned-td21'})
        handler.path = '/stream?deviceId=owned-c400&deviceId=owned-td21'
        with self.assertRaises(ValueError):
            routed_query(handler, {})

    def setUp(self):
        item = patch("playback_media.activity", side_effect=lambda: nullcontext())
        item.start()
        self.addCleanup(item.stop)
        self.auth = MediaAuth()
        self.password = "A" * 64
        self.peer = "10.23.0.80"

    def authorization(self, uri="/stream"):
        challenge = self.auth.challenge(self.peer, self.password)
        proof = digest(challenge, self.password, "CLIENT-NONCE")
        if uri != "/stream":
            fields = parse_keqv_list(parse_http_list(proof[7:]))
            md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
            response = md5(":".join((md5("admin:Tapo Hub:" + self.password), fields["nonce"],
                                     "00000001", "CLIENT-NONCE", "auth", md5("POST:" + uri))))
            proof = proof.replace('uri="/stream"', 'uri="' + uri + '"').replace(fields["response"], response)
        return proof

    def test_digest_proof_is_peer_bound_one_use_and_invalidated_by_password_change(self):
        proof = self.authorization()
        self.assertTrue(self.auth.verify(proof, self.peer, self.password))
        self.assertFalse(self.auth.verify(proof, self.peer, self.password))
        self.assertFalse(self.auth.verify(self.authorization(), "10.23.0.81", self.password))
        self.assertFalse(self.auth.verify(self.authorization(), self.peer, "B"*64))
        self.assertFalse(self.auth.verify(self.authorization().replace("response=", "bad="), self.peer, self.password))

    def test_ios_digest_signs_the_requested_query_string_and_rejects_another_uri(self):
        uri = "/stream?deviceId=owned-child&playerId=test-player"
        self.assertTrue(self.auth.verify(self.authorization(uri), self.peer, self.password, uri))
        self.assertFalse(self.auth.verify(self.authorization(uri), self.peer, self.password, "/stream?playerId=other"))
        # Existing reference clients still sign /stream even when requesting a player query.
        self.assertTrue(self.auth.verify(self.authorization(), self.peer, self.password, uri))

    def test_unauthenticated_request_never_reads_media_and_can_retry_on_same_socket(self):
        handler = SimpleNamespace(path="/stream", connection=Mock(), headers={}, client_address=(self.peer, 123),
                                  server=SimpleNamespace(setup=SimpleNamespace(auth=SimpleNamespace(password_hash=self.password)),
                                                         media_auth=self.auth))
        handler.send_response = handler.send_header = handler.end_headers = Mock()
        serve_playback(handler)
        self.assertFalse(handler.close_connection)
        self.assertEqual(len(self.auth.challenges), 1)

    def test_stream_is_authenticated_encrypted_and_ends_only_after_successful_remux(self, encrypted_command=False, native_boundary=False, thumbnail=False, face_photos=False, continuous=False):
        query = {"start_time": "100", "end_time": "102", "channels": [0]}
        if thumbnail:
            query = {"start_time": "100", "channels": [0], "media_type": 2}
        if face_photos:
            query = {"type": "get_face", "face_id": ["7", "8"]}
        request = json.dumps({"type": "request", "seq": 44, "params": {"method": "get",
                             "image" if face_photos else "download" if thumbnail else "playback": query}}).encode()
        if encrypted_command:
            request = encrypt(request, "a"*32, self.password)
        payload = ((b"client-boundary" if native_boundary else b"--client-boundary")
                   + b"\r\nContent-Type: application/json\r\nX-If-Encrypt: "
                   + str(int(encrypted_command)).encode() + b"\r\nContent-Length: " + str(len(request)).encode() + b"\r\n\r\n" + request)
        player = Mock()
        player.stream_files.return_value = ({"path": "/isolated/owned.mp4", "start": 100}, ["/isolated/owned.mp4"], 0, 2)
        if continuous:
            directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
            rows = [{'path': directory / ('part-' + str(i) + '.mp4'), 'start': 100 + i * 30,
                     'duration': 30.0} for i in range(2)]
            player.stream_files.return_value = (rows[0], rows, 28, 2)
        player.thumbnail.return_value = ({"start": 100}, b"\xff\xd8owned\xff\xd9")
        faces = Mock()
        faces.media_photos.return_value = [("7", b"\xff\xd8owned\xff\xd9"), ("8", None)]
        uri = "/stream?playerId=ios-test-player"
        handler = SimpleNamespace(path=uri, connection=Mock(), headers={"Authorization": self.authorization(uri),
            "Content-Type": "multipart/mixed;boundary=client-boundary"}, client_address=(self.peer, 123),
            rfile=io.BytesIO(payload), wfile=io.BytesIO(), server=SimpleNamespace(playback=player, faces=faces,
            setup=SimpleNamespace(auth=SimpleNamespace(password_hash=self.password)), media_auth=self.auth))
        handler.send_response = handler.end_headers = Mock()
        response_headers = {}
        handler.send_header = lambda key, value: response_headers.update({key: value})
        transport_stream = b"\x47" + b"\x00" * 187
        process = Mock(stdout=io.BytesIO(transport_stream))
        process.wait.return_value = process.poll.return_value = 0
        def start_process(arguments, **kwargs):
            if continuous:
                manifest = Path(arguments[arguments.index('-i') + 1]).read_text()
                self.assertEqual(manifest.count('duration 30.0\n'), 2)
                self.assertIn('part-1.mp4', manifest)
            return process
        with patch("playback_media.subprocess.Popen", side_effect=start_process), \
                patch("playback_media.secrets.token_hex", return_value="a"*32):
            serve_playback(handler)
        if face_photos:
            faces.media_photos.assert_called_once_with(query)
            player.stream_files.assert_not_called()
        elif thumbnail:
            player.thumbnail.assert_called_once_with(query)
            player.stream_files.assert_not_called()
        else:
            player.stream_files.assert_called_once_with(query)
        for field in ('cipher="AES_128_CBC"', 'padding="PKCS7_16"', 'algorithm="MD5"', 'encrypt_type="3"'):
            self.assertIn(field, response_headers["Key-Exchange"])
        self.assertEqual(handler.protocol_version, "HTTP/1.0")
        stream = io.BytesIO(handler.wfile.getvalue())
        records = []
        while stream.tell() < len(stream.getvalue()):
            self.assertEqual(stream.readline(), (BOUNDARY if native_boundary else b"--" + BOUNDARY) + b"\r\n")
            fields = headers(stream)
            data = stream.read(int(fields["content-length"]))
            self.assertEqual(stream.read(2), b"\r\n")
            if fields["x-if-encrypt"] == "1":
                data = decrypt_media(data, response_headers["Key-Exchange"], self.password)
            records.append((fields["content-type"], data))
        self.assertEqual(json.loads(records[0][1])["params"]["error_code"], 0)
        self.assertIsInstance(json.loads(records[0][1])["params"]["session_id"], str)
        self.assertEqual(records[1], ("image/jpeg", b"\xff\xd8owned\xff\xd9") if thumbnail or face_photos else ("video/mp2t", transport_stream))
        if face_photos:
            self.assertEqual(json.loads(records[0][1])["params"]["face_status"], ["exist", "error"])
            self.assertEqual(json.loads(records[2][1])["params"]["status"], "image_ended")
            self.assertEqual(json.loads(records[2][1])["params"]["face_id"], "7")
        self.assertEqual(json.loads(records[-1][1])["params"]["status"], "finished")
        self.assertTrue(handler.close_connection)

    def test_encrypted_playback_command_reaches_the_same_validated_clip(self):
        self.test_stream_is_authenticated_encrypted_and_ends_only_after_successful_remux(encrypted_command=True)

    def test_continuous_manifest_supplies_durations_required_for_input_seeking(self):
        self.test_stream_is_authenticated_encrypted_and_ends_only_after_successful_remux(
            encrypted_command=True, continuous=True)

    def test_native_literal_boundary_works_with_an_encrypted_command_and_response(self):
        self.test_stream_is_authenticated_encrypted_and_ends_only_after_successful_remux(encrypted_command=True, native_boundary=True)

    def test_recorded_thumbnail_uses_authenticated_encrypted_native_download(self):
        self.test_stream_is_authenticated_encrypted_and_ends_only_after_successful_remux(encrypted_command=True, thumbnail=True)

    def test_saved_face_photos_use_encrypted_media_and_native_completion_notifications(self):
        self.test_stream_is_authenticated_encrypted_and_ends_only_after_successful_remux(
            encrypted_command=True, native_boundary=True, face_photos=True)

    def test_media_slots_are_bounded(self):
        self.assertTrue(self.auth.slots.acquire(False))
        self.assertTrue(self.auth.slots.acquire(False))
        self.assertFalse(self.auth.slots.acquire(False))
