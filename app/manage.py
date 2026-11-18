"""Guided setup and health checks for a dedicated Tapo Hub LXC."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
import time
import re
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

APP = Path(__file__).resolve().parent
ETC = Path('/etc/tapo-hub')
STATE = Path('/var/lib/tapo-hub')
STORE = STATE/'recordings'
MODELS = STATE/'models'
TERMS = 'https://github.com/deepinsight/insightface/tree/master/python-package#license'


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def ask(prompt, default=''):
    answer = input(f'{prompt}' + (f' [{default}]' if default else '') + ': ').strip()
    return answer or default


def validate_cameras(cameras, network):
    from camera_registry import normalize_mac, camera_supported
    if not isinstance(cameras, list) or not 0 <= len(cameras) <= 3:
        raise ValueError('Enter up to three cameras; other devices will not be discovered')
    devices, addresses = {}, set()
    for camera in cameras:
        if not isinstance(camera, dict) or set(camera) - {'mac', 'model', 'ip', 'hardware_version', 'continuous'}:
            raise ValueError('Invalid camera fields')
        mac = normalize_mac(camera['mac'])
        address = ipaddress.IPv4Address(camera['ip'])
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError('Camera IP must belong to the selected LAN')
        if mac in devices or str(address) in addresses or not camera_supported(camera):
            raise ValueError('Duplicate camera or unsupported model/hardware')
        if type(camera.get('continuous', False)) is not bool or (camera.get('continuous') and camera['model'] != 'TC70'):
            raise ValueError('Continuous recording is supported only for configured TC70 cameras')
        addresses.add(str(address))
        devices[mac] = {'model': camera['model'], 'seed_ip': str(address), 'last_ip': None,
                        'last_seen': 0, 'hardware_version': camera.get('hardware_version', '')}
    return {'devices': devices, 'pending': []}


def prepare_store(path=STORE):
    path = Path(path)
    if path.is_symlink() or not os.path.ismount(path) or path.stat().st_dev == Path('/').stat().st_dev:
        raise ValueError('A dedicated recording volume must be mounted at /var/lib/tapo-hub/recordings; the root disk is refused')
    marker = path/'.tapo-hub-store'
    if marker.is_symlink():
        raise ValueError('Unsafe recording-store marker')
    if not marker.exists():
        if any(item.name != 'lost+found' for item in path.iterdir()):
            raise ValueError('The selected volume contains other data. Choose an empty dedicated volume; nothing was changed')
        atomic_json(marker, {'application': 'tapo-hub', 'format': 1})
    elif json.loads(marker.read_text()) != {'application': 'tapo-hub', 'format': 1}:
        raise ValueError('This volume does not belong to Tapo Hub')
    os.chmod(path, 0o700)
    for name in ('events', 'native-captures', 'failed-uploads'):
        (path/name).mkdir(mode=0o700, exist_ok=True)


def download(url, maximum):
    if not url.startswith('https://'):
        raise ValueError('Model downloads require HTTPS')
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('Model download exceeds its size limit')
    return data


def install_models(choice, model_path=None, accepted=False):
    detector = json.loads((APP/'face_models.json').read_text())['models'][0]
    reference = json.loads((APP/'arcface_model.json').read_text())
    MODELS.mkdir(mode=0o755, parents=True, exist_ok=True)
    if choice == 'download':
        if not accepted:
            raise ValueError(f'Review the model usage terms before downloading: {TERMS}')
        archive = download(reference['archive_source'], 80_000_000)
        if hashlib.sha256(archive).hexdigest() != reference['archive_sha256']:
            raise ValueError('ArcFace archive checksum mismatch')
        import io
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            names = [name for name in package.namelist() if Path(name).name == reference['model_file']]
            if len(names) != 1 or package.getinfo(names[0]).file_size > 25_000_000:
                raise ValueError('Unexpected ArcFace archive contents')
            recognition = package.read(names[0])
        if hashlib.sha256(recognition).hexdigest() != reference['model_sha256']:
            raise ValueError('ArcFace model checksum mismatch')
    elif choice == 'file':
        source = Path(model_path)
        if not source.is_file() or source.is_symlink() or not 0 < source.stat().st_size <= 300_000_000:
            raise ValueError('Choose a compatible ArcFace ONNX file under 300 MB')
        recognition = source.read_bytes()
        reference.update(model_sha256=hashlib.sha256(recognition).hexdigest(),
                         model_id='custom-arcface-' + hashlib.sha256(recognition).hexdigest()[:16])
    else:
        return None
    detection = download(detector['source'], 1_000_000)
    if hashlib.sha256(detection).hexdigest() != detector['sha256']:
        raise ValueError('YuNet model checksum mismatch')
    # Probe the supplied network before installing or advertising it.
    import cv2
    import numpy as np
    with tempfile.TemporaryDirectory() as work:
        candidate = Path(work)/'model.onnx'
        candidate.write_bytes(recognition)
        network = cv2.dnn.readNetFromONNX(str(candidate))
        network.setInput(np.zeros((1, 3, 112, 112), dtype=np.float32))
        if network.forward().size != 512:
            raise ValueError('The model must accept 112x112 RGB input and return a 512-dimensional ArcFace embedding')
    (MODELS/detector['name']).write_bytes(detection)
    (MODELS/'w600k_mbf.onnx').write_bytes(recognition)
    atomic_json(MODELS/'manifest.json', {'models': [detector]})
    atomic_json(MODELS/'arcface_manifest.json', reference)
    license_url = 'https://raw.githubusercontent.com/opencv/opencv_zoo/' + json.loads((APP/'face_models.json').read_text())['opencv_zoo_commit'] + '/models/face_detection_yunet/LICENSE'
    (MODELS/'face_detection_yunet.LICENSE').write_bytes(download(license_url, 20_000))
    return reference['model_id']


def discovery_guide():
    print('''
NEXT: DISCOVER AND LINK THE HUB
1. Connect this LXC to the same LAN/VLAN as the phone and selected cameras.
   Reserve its IP address in DHCP. Allow LAN broadcasts; disable Wi-Fi client isolation.
2. Run `tapo-hub doctor`. The hub should answer local discovery and authenticated HTTPS.
3. In Tapo: + -> Add Device -> Hubs -> H500 -> Ethernet/wired setup.
   Allow Local Network access on iPhone and keep the phone on this Wi-Fi network.
4. After the hub is added, open Add Existing Device and select ONE configured camera.
   For a sleeping TD21/C400, open its live view briefly, then return and refresh.
   Entries are authorized by MAC; the supplied IP is only an initial discovery hint.
5. Trigger a natural event and check H500 -> Playback -> the camera and today's date.
   Discovery/pairing success alone does not prove that a recording reached the server.
6. Open Face Recognition, add a familiar profile, and inspect the event's real result.

If no hub is found: check `tapo-hub doctor`, the selected subnet, the LXC bridge,
phone Local Network permission, client isolation and UDP 20002/20015.
If a camera is missing: check its MAC/IP/model/hardware and wake a battery camera.
If playback is empty: check the date/timezone and `tapo-hub status`; interrupted
uploads cannot create a complete recording. Native face push is not implemented.
Do not reset or unlink working cameras as a routine troubleshooting step.
''')


def configure(args):
    from settings import validate
    print('Tapo Hub setup — configuration stays in this LXC; no account password is requested.')
    print('Storage: choose/create a NEW dedicated Proxmox volume, mounted at ' + str(STORE))
    print('Existing volumes containing other application data are refused. No format command is run here.')
    prepare_store()
    if args.config_file:
        config = json.loads(Path(args.config_file).read_text())
    else:
        addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address'], text=True))
        candidates = [entry for interface in addresses if interface['ifname'] != 'lo'
                      for entry in interface.get('addr_info', []) if entry['scope'] == 'global']
        hint = candidates[0] if len(candidates) == 1 else {}
        hub = ask('Hub IPv4 address (must belong to this LXC)', hint.get('local', ''))
        network_hint = str(ipaddress.IPv4Network(f"{hub}/{hint.get('prefixlen', 24)}", strict=False))
        lan = ask('LAN subnet containing the hub, phone and cameras', network_hint)
        timezone = ask('IANA timezone, for example Etc/UTC or Europe/London', 'Etc/UTC')
        print('Enter the cameras this hub may discover. Supported: TD21, C400 hardware 2.x, TC70 hardware 5.x.')
        cameras = []
        for number in range(3):
            model = ask(f'Camera {number + 1} model (blank finishes)').upper()
            if not model:
                break
            hardware = ask('Hardware version from Device Info', '1.0' if model == 'TD21' else '')
            cameras.append({'model': model, 'hardware_version': hardware,
                            'mac': ask('Camera MAC address from Tapo Device Info'),
                            'ip': ask('Current camera IPv4 address'),
                            'continuous': model == 'TC70' and ask('Enable continuous hub recording for this TC70? yes/no', 'no') == 'yes'})
        config = {'hub_ip': hub, 'lan_cidr': lan, 'timezone': timezone,
                  'recording_path': str(STORE), 'cameras': cameras}
    validate(config)
    ZoneInfo(config.get('timezone', 'Etc/UTC'))
    registry = validate_cameras(config['cameras'], ipaddress.IPv4Network(config['lan_cidr'], strict=False))
    actual = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address'], text=True))
    if config['hub_ip'] not in {a['local'] for interface in actual for a in interface.get('addr_info', [])}:
        raise ValueError('Hub IP is not assigned to this LXC')
    choice = args.models
    model_path = args.model_path
    accepted = args.accept_model_terms
    if choice is None and not args.config_file:
        print(f'Local AI is installed. ArcFace pretrained weights have separate terms: {TERMS}')
        choice = {'1': 'download', '2': 'file', '3': 'later'}[ask('Models: 1 download tested buffalo_sc, 2 use licensed ONNX file, 3 set up later', '3')]
        if choice == 'download':
            accepted = ask('Enter ACCEPT only if your use is authorized under the linked model terms') == 'ACCEPT'
        if choice == 'file':
            model_path = ask('Path to your compatible licensed ArcFace ONNX file')
    firewall_active = subprocess.run(['systemctl', 'is-active', '--quiet', 'tapo-hub-lan-only']).returncode == 0
    if firewall_active and choice in ('download', 'file'):
        subprocess.run(['systemctl', 'stop', 'tapo-hub-lan-only'], check=True)
    try:
        model_id = install_models(choice or 'later', model_path, accepted)
    finally:
        if firewall_active and choice in ('download', 'file'):
            subprocess.run(['systemctl', 'start', 'tapo-hub-lan-only'], check=True)
    existing_model = json.loads((MODELS/'arcface_manifest.json').read_text())['model_id'] if (MODELS/'arcface_manifest.json').exists() else None
    config['face_model_id'] = model_id or existing_model or 'arcface-buffalo-sc-w600k_mbf-v1'
    subprocess.run(['systemctl', 'stop', 'tapo-hub', 'tapo-hub-face'], check=True)
    atomic_json(ETC/'config.json', config)
    atomic_json(ETC/'cameras.json', registry)
    STATE.mkdir(mode=0o700, exist_ok=True)
    state_file = STATE/'state.json'
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    clock = datetime.now(ZoneInfo(config.get('timezone', 'Etc/UTC')))
    seconds = int((clock.utcoffset() - clock.dst()).total_seconds())
    hours, minutes = divmod(abs(seconds) // 60, 60)
    state.update(zone_id=config.get('timezone', 'Etc/UTC'), timezone=f"UTC{'+' if seconds >= 0 else '-'}{hours:02}:{minutes:02}")
    atomic_json(state_file, state)
    if not (ETC/'key.pem').exists():
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
                        '-subj', '/CN=Tapo Hub', '-keyout', str(ETC/'key.pem'), '-out', str(ETC/'cert.pem')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        os.chmod(ETC/'key.pem', 0o600)
    (ETC/'lan-only.nft').write_text('destroy table inet tapo_hub\ntable inet tapo_hub {\n'
        ' chain output { type filter hook output priority 10; policy drop;\n'
        ' oifname "lo" accept\n ip daddr ' + str(ipaddress.IPv4Network(config['lan_cidr'], strict=False)) + ' accept\n'
        ' ip daddr 255.255.255.255 udp dport 67 accept\n counter reject with icmpx type admin-prohibited\n }\n}\n')
    if model_id:
        from face_database import FaceDatabase
        database = FaceDatabase(STORE/'faces'/'faces.duckdb')
        database.set_enabled(True)
        database.close()
    subprocess.run(['systemctl', 'enable', '--now', 'tapo-hub-lan-only', 'tapo-hub-face', 'tapo-hub'], check=True)
    for camera in config['cameras']:
        if camera.get('continuous'):
            from camera_registry import normalize_mac
            subprocess.run(['systemctl', 'enable', '--now', f"tapo-hub-continuous@{normalize_mac(camera['mac'])}.service"], check=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            health = subprocess.run([sys.executable, str(APP/'manage.py'), 'doctor'],
                                    capture_output=True, text=True, timeout=5)
            ready = json.loads(health.stdout) if health.returncode == 0 else {}
            if ready.get('hub') == 'ready' and (not existing_model or ready.get('local_face_ai') == 'ready'):
                print('Verified local discovery, encrypted control, recording storage and configured AI readiness.')
                break
        except (subprocess.TimeoutExpired, ValueError):
            pass
        time.sleep(1)
    else:
        raise ValueError('Configuration saved, but health checks did not pass. Run tapo-hub status and inspect the service journal before pairing')
    print('Configuration saved. Local AI: ' + ('models validated' if model_id or existing_model else 'installed; model setup still required'))
    discovery_guide()


def doctor():
    from settings import CONFIG, validate
    validate(CONFIG)
    from recording_retention import check_store
    check_store()
    import socket
    from hub_lab import packet, decode_probe
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(3)
        stream.sendto(packet({}), (CONFIG['hub_ip'], 20002))
        data, _ = stream.recvfrom(8192)
    discovery = decode_probe(data)['result']
    state_file = STATE/'state.json'
    state = json.loads(state_file.read_text())
    from camera_probe import CameraProbe
    probe = CameraProbe(CONFIG['hub_ip'], state.get('password_hash', __import__('hub_lab').SetupAuth.password_hash))
    probe.login()
    result = probe.read('getDeviceInfo')['result']['device_info']['basic_info']
    if discovery['device_id'] != result['dev_id']:
        raise ValueError('Discovery/control identity mismatch')
    from face_inference import FaceClient
    from storage_status import disk_info
    print(json.dumps({'hub': 'ready', 'discovery_control_identity': 'consistent',
        'storage': disk_info()['status'], 'configured_cameras': len(CONFIG['cameras']),
        'local_face_ai': 'ready' if FaceClient().ready() else 'models/worker not ready'}, indent=2))


def update():
    source = json.loads((ETC/'source.json').read_text())
    repository = source['repository']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Configure the published source repository before updating')
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'tapo-hub-lan-only']).returncode == 0
    if active:
        subprocess.run(['systemctl', 'stop', 'tapo-hub-lan-only'], check=True)
    try:
        content = download(f'https://raw.githubusercontent.com/{repository}/main/ct/tapo-hub.sh', 256_000)
        with tempfile.TemporaryDirectory() as work:
            script = Path(work)/'update.sh'
            script.write_bytes(content)
            subprocess.run(['bash', str(script)], check=True,
                           env={**os.environ, 'var_repository': repository})
    finally:
        if active:
            subprocess.run(['systemctl', 'start', 'tapo-hub-lan-only'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    setup = sub.add_parser('configure', help='Guided network, cameras, storage and local AI setup')
    setup.add_argument('--config-file', type=Path, help='Private unattended configuration JSON')
    setup.add_argument('--models', choices=('download', 'file', 'later'))
    setup.add_argument('--model-path')
    setup.add_argument('--accept-model-terms', action='store_true')
    models = sub.add_parser('models', help='Set up local AI models using existing hub configuration')
    models.add_argument('--models', choices=('download', 'file'), required=True)
    models.add_argument('--model-path')
    models.add_argument('--accept-model-terms', action='store_true')
    sub.add_parser('update', help='Update from the configured public release repository')
    sub.add_parser('doctor', help='Check storage, local discovery, encrypted control and local AI')
    sub.add_parser('guide', help='Show the guided Tapo pairing and first-recording checks')
    sub.add_parser('status', help='Show service health without credentials')
    args = parser.parse_args()
    try:
        if args.command in ('configure', 'models', 'update'):
            if os.geteuid() != 0:
                raise ValueError('Run configuration as root inside the dedicated LXC')
            if args.command == 'update':
                update()
            else:
                if args.command == 'models':
                    args.config_file = ETC/'config.json'
                configure(args)
        elif args.command == 'doctor':
            doctor()
        elif args.command == 'guide':
            discovery_guide()
        else:
            subprocess.run(['systemctl', '--no-pager', 'status', 'tapo-hub', 'tapo-hub-face'], check=False)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Tapo Hub: {error}\nRun tapo-hub guide for discovery steps.\n')


if __name__ == '__main__':
    main()
