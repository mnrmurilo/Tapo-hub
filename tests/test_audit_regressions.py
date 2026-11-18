"""Regression cases from the initial reliability/security audit; no real cameras."""
import base64
from contextlib import nullcontext
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import manage
from hub_lab import SetupAuth, sha
from tls_server import BoundedHTTPServer
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ManagementRecoveryTests(unittest.TestCase):
    def test_update_download_failure_restores_network_without_stopping_hub(self):
        with tempfile.TemporaryDirectory() as work:
            etc = Path(work)
            (etc/'source.json').write_text(json.dumps({'repository': 'example/Tapo-hub'}))
            with patch.object(manage, 'ETC', etc), patch.object(manage.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, \
                    patch.object(manage, 'download', side_effect=OSError('download failed')):
                with self.assertRaises(OSError):
                    manage.update()
            calls = [c.args[0] for c in run.call_args_list]
            self.assertFalse(any(c[:2] == ['systemctl', 'stop'] for c in calls))
            self.assertIn(['nft', '-f', str(etc/'lan-only.nft')], calls)

    def test_recorder_disable_is_reconciled_before_starting_hub(self):
        unit = 'tapo-hub-continuous@02:00:00:00:00:01.service'
        with patch.object(manage.subprocess, 'run', return_value=SimpleNamespace(stdout=unit+' enabled\n')) as run:
            self.assertEqual(manage.reconcile_recorders([]), set())
            run.assert_any_call(['systemctl', 'disable', '--now', unit], check=True)

    def test_selected_continuous_option_survives_validation_and_rejects_two_recorders(self):
        import ipaddress
        camera = {'model': 'TC70', 'hardware_version': '5.0', 'mac': '02:00:00:00:00:01',
                  'ip': '10.23.0.10', 'continuous': True}
        lan = ipaddress.IPv4Network('10.23.0.0/24')
        self.assertTrue(manage.validate_cameras([camera], lan)['devices'][camera['mac']]['continuous'])
        with self.assertRaises(ValueError):
            manage.validate_cameras([camera, {**camera, 'mac': '02:00:00:00:00:02', 'ip': '10.23.0.11'}], lan)

    def test_changed_firewall_is_applied_and_failed_check_preserves_previous_file(self):
        with tempfile.TemporaryDirectory() as work:
            etc = Path(work); target = etc/'lan-only.nft'; target.write_text('old rules')
            with patch.object(manage, 'ETC', etc), patch.object(manage.subprocess, 'run') as run:
                manage.apply_firewall('10.24.0.0/24')
                self.assertIn('10.24.0.0/24', target.read_text())
                self.assertEqual([c.args[0][:2] for c in run.call_args_list], [['nft', '--check'], ['nft', '-f']])
                previous = target.read_bytes()
                run.side_effect = subprocess.CalledProcessError(1, 'nft')
                with self.assertRaises(subprocess.CalledProcessError):
                    manage.apply_firewall('10.25.0.0/24')
                self.assertEqual(target.read_bytes(), previous)

    def test_failed_configuration_restores_files_models_and_previously_running_services(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); etc = root/'etc'; state = root/'state'; models = state/'models'
            etc.mkdir(); models.mkdir(parents=True)
            for path in (etc/'config.json', etc/'cameras.json', state/'state.json'):
                path.write_text('{}')
            (etc/'lan-only.nft').write_text('old firewall')
            (models/'model').write_text('working model')
            with patch.object(manage, 'ETC', etc), patch.object(manage, 'STATE', state), patch.object(manage, 'MODELS', models), \
                    patch.object(manage.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='')) as run:
                with self.assertRaisesRegex(ValueError, 'synthetic'):
                    with manage.configuration_changes(True):
                        (etc/'config.json').write_text('new config')
                        (models/'model').write_text('new weights')
                        raise ValueError('synthetic failure')
                self.assertEqual((etc/'config.json').read_text(), '{}')
                self.assertEqual((models/'model').read_text(), 'working model')
                run.assert_any_call(['systemctl', 'start', 'tapo-hub', 'tapo-hub-face'], check=True)

    def test_failed_license_download_preserves_working_model_bundle(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); app = root/'app'; models = root/'models'; app.mkdir(); models.mkdir()
            detector, weights = b'detector', b'new weights'
            source = root/'input.onnx'; source.write_bytes(weights)
            (models/'w600k_mbf.onnx').write_bytes(b'working weights')
            (models/'arcface_manifest.json').write_text('old manifest')
            (app/'face_models.json').write_text(json.dumps({'models': [{'name': 'detector.onnx',
                'source': 'https://example.invalid/model', 'sha256': hashlib.sha256(detector).hexdigest()}],
                'opencv_zoo_commit': 'synthetic'}))
            (app/'arcface_model.json').write_text(json.dumps({'model_id': 'old', 'embedding_dimensions': 512}))
            network = Mock(); network.forward.return_value = SimpleNamespace(size=512)
            with patch.object(manage, 'APP', app), patch.object(manage, 'MODELS', models), \
                    patch.object(manage, 'download', side_effect=[detector, OSError('license failed')]), \
                    patch('cv2.dnn.readNetFromONNX', return_value=network):
                with self.assertRaises(OSError):
                    manage.install_models('file', source)
            self.assertEqual((models/'w600k_mbf.onnx').read_bytes(), b'working weights')
            self.assertEqual((models/'arcface_manifest.json').read_text(), 'old manifest')
            replace = os.replace
            def fail_switch(source, destination):
                if Path(source).name == 'bundle' and Path(destination) == models:
                    raise OSError('synthetic bundle-switch failure')
                return replace(source, destination)
            with patch.object(manage, 'APP', app), patch.object(manage, 'MODELS', models), \
                    patch.object(manage, 'download', side_effect=[detector, b'license']), \
                    patch('cv2.dnn.readNetFromONNX', return_value=network), patch.object(manage.os, 'replace', side_effect=fail_switch):
                with self.assertRaisesRegex(OSError, 'bundle-switch'):
                    manage.install_models('file', source)
            self.assertEqual((models/'w600k_mbf.onnx').read_bytes(), b'working weights')
            self.assertEqual((models/'arcface_manifest.json').read_text(), 'old manifest')


    def test_helper_failed_release_deployment_restores_backup_and_restarts_services(self):
        script = (Path(__file__).resolve().parents[1]/'ct'/'tapo-hub.sh').read_text()
        function = script[script.index('function update_script() {'):script.index('\n}\n')+3]
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); (root/'etc').mkdir(); (root/'opt').mkdir()
            (root/'etc'/'source.json').write_text(json.dumps({'repository': 'example/Tapo-hub'}))
            function = function.replace('/etc/tapo-hub', str(root/'etc')).replace('/opt/tapo-hub', str(root/'opt'/'app'))
            prefix = '''set -e
header_info() { :; }
check_container_storage() { :; }
check_container_resources() { :; }
msg_info() { :; }
msg_ok() { :; }
check_for_gh_release() { return 0; }
systemctl() { echo "systemctl $*" >>"$AUDIT_CALLS"; }
create_backup() { touch "$BACKUP_DIR/.manifest"; }
restore_backup() { echo restore >>"$AUDIT_CALLS"; }
fetch_and_deploy_gh_release() { return 42; }
'''
            result = subprocess.run(['bash', '-c', prefix+function+'\nupdate_script\n'],
                                    env={**os.environ, 'AUDIT_CALLS': str(root/'calls')}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 42, result.stderr)
            calls = (root/'calls').read_text()
            self.assertIn('restore\n', calls)
            self.assertIn('systemctl start tapo-hub-face tapo-hub', calls)


class RuntimeRegressionTests(unittest.TestCase):
    def test_tc70_without_continuous_opt_in_cannot_claim_working_hub_storage(self):
        from test_native_storage import NativeStorageTests
        case = NativeStorageTests(); case.setUp(); self.addCleanup(case.doCleanups)
        case.cameras.devices[case.mac].update(model='TC70', hardware_version='5.0', continuous=False)
        case.params['general_camera_manage']['storage_info']['basic_info']['model'] = 'TC70'
        result = case.storage.command(case.params, '10.23.0.52')
        self.assertNotEqual(result['error_code'], 0)
        self.assertEqual(case.storage.devices, {})

    def test_full_gallery_sync_returns_more_than_one_hundred_profiles(self):
        from test_face_api import FaceAPITests
        case = FaceAPITests(); case.setUp(); self.addCleanup(case.doCleanups)
        case.enroll()
        case.db.connection.execute('''INSERT INTO faces(name,tag,image,embedding,created,fresh,modified,verified,embedding_model)
            SELECT name,tag,image,embedding,created,fresh,modified,verified,embedding_model FROM faces CROSS JOIN range(104)''')
        reply = case.call('searchFacesInfo', 'search_faces_info', {'update_time': 0})['result']['face_detection']['search_faces_info_result']
        self.assertEqual(len(reply['faces_infos']), 105)
        preview = case.call('searchFacesInfo', 'search_faces_info', {'update_time': 0, 'trans_limit': 4})['result']['face_detection']['search_faces_info_result']
        self.assertEqual(len(preview['faces_infos']), 4)
        self.assertEqual(preview['search_time'], 0)  # Preview does not claim to synchronize unseen profiles.

    def test_full_unknown_gallery_does_not_block_familiar_links(self):
        from test_face_api import FaceAPITests
        from face_database import FaceCapacityError
        case = FaceAPITests(); case.setUp(); self.addCleanup(case.doCleanups)
        familiar = case.enroll()
        case.db.connection.execute('''INSERT INTO faces(name,tag,image,embedding,created,fresh,modified,verified,embedding_model)
            SELECT '', 'stranger',image,embedding,created,fresh,modified,false,embedding_model FROM faces CROSS JOIN range(300)''')
        with self.assertRaises(FaceCapacityError):
            case.db.add('', 'stranger', case.image, case.face['embedding'])
        # Familiar capacity is independent of unknown capacity.
        case.db.add('Another familiar', 'familiar', case.image, case.face['embedding'])
        case.db.set_enabled(True)
        key = 'event-'+'a'*24
        case.playback.recordings.return_value = [{'file_id': key, 'path': 'synthetic.mp4', 'start': 1794400000, 'end': 1794400030}]
        case.client.call.return_value = {'faces': [case.face, case.face]}
        with patch.object(case.db, 'match', side_effect=[None, familiar]):
            self.assertTrue(case.api.process_events())
        self.assertEqual(case.db.events(familiar), [(key, 1794400000)])
        self.assertTrue(case.db.analyzed(key))

    def test_unchanged_recording_indexes_are_not_reopened_and_changes_are_seen(self):
        from test_recording_playback import PlaybackQueryTests
        case = PlaybackQueryTests(); case.setUp(); self.addCleanup(case.doCleanups)
        original = Path.read_text; opened = []
        def read(path, *args, **kwargs):
            opened.append(path)
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', read):
            self.assertEqual(len(case.playback.recordings({})), 1)
            self.assertEqual(len(case.playback.recordings({})), 1)
            self.assertEqual(len(opened), 1)
            index = case.events/'event-owned.mp4.json'
            data = json.loads(original(index)); data['source_time'] += 5; index.write_text(json.dumps(data))
            self.assertEqual(case.playback.recordings({})[0]['start'], case.start+5)
            self.assertEqual(len(opened), 2)
            index.unlink()
            self.assertEqual(case.playback.recordings({}), [])
            self.assertEqual(case.playback._indexes, {})

    def test_slow_authenticated_operation_does_not_block_login_or_allow_replay(self):
        auth = SetupAuth(sha('synthetic')); peer = '192.0.2.1'; nonce = 'first'
        server_nonce = auth.login({'username': 'admin', 'cnonce': nonce}, peer)['result']['data']['nonce']
        proof = sha(auth.password_hash+nonce+server_nonce)+nonce+server_nonce
        token = auth.login({'username': 'admin', 'cnonce': nonce, 'digest_passwd': proof}, peer)['result']['stok']
        session = auth.sessions[token]
        padder = padding.PKCS7(128).padder()
        data = padder.update(b'{"method":"slow"}')+padder.finalize()
        encryptor = Cipher(algorithms.AES(session['key']), modes.CBC(session['iv'])).encryptor()
        raw = json.dumps({'method': 'securePassthrough', 'params': {'request': base64.b64encode(encryptor.update(data)+encryptor.finalize()).decode()}}).encode()
        headers = {'Seq': '100', 'Tapo_tag': sha(sha(auth.password_hash+nonce)+raw.decode()+'100')}
        entered, finish, logged_in = threading.Event(), threading.Event(), threading.Event()
        def slow(_):
            entered.set(); finish.wait(2); return {'error_code': 0}
        worker = threading.Thread(target=lambda: auth.secure(token, peer, raw, headers, slow))
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            login = threading.Thread(target=lambda: (auth.login({'username': 'admin', 'cnonce': 'other'}, '192.0.2.2'), logged_in.set()))
            login.start()
            self.assertTrue(logged_in.wait(.5), 'Unrelated login was blocked by dispatch')
            self.assertNotEqual(auth.secure(token, peer, raw, headers, lambda _: self.fail('Replay dispatched'))['error_code'], 0)
        finally:
            finish.set(); worker.join(3); login.join(3)

    def test_idle_playback_connections_are_bounded_and_expire_before_authentication(self):
        class Reply(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
        class Server(BoundedHTTPServer):
            max_connections = 2
            request_timeout = .25
        server = Server(('127.0.0.1', 0), Reply)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        clients = []
        try:
            for _ in range(2):
                clients.append(socket.create_connection(server.server_address, timeout=2))
            deadline = time.monotonic()+1
            while server.slots._value and time.monotonic() < deadline:
                time.sleep(.01)
            with socket.create_connection(server.server_address, timeout=1) as rejected:
                self.assertEqual(rejected.recv(1), b'')
            for client in clients:
                self.assertEqual(client.recv(1), b'')
            deadline = time.monotonic()+1
            while server.slots._value != 2 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(server.slots._value, 2)
        finally:
            for client in clients: client.close()
            server.shutdown(); server.server_close(); worker.join(2)
