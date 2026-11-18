"""Select the tested hub for the configured TC70 v5, preserving its recording schedule."""
import json
from pathlib import Path
import time

from camera_media import STORE
from camera_probe import CameraProbe, probe
from camera_registry import normalize_mac
from continuous_recording import STATE, atomic_json


def main():
    devices = json.loads((STATE / 'cameras.json').read_text())['devices']
    candidates = [mac for mac, item in devices.items() if item['model'] == 'TC70']
    if len(candidates) != 1:
        raise ValueError('Expected one configured TC70')
    mac = candidates[0]
    camera_info = probe(mac, str(STATE / 'cameras.json'), str(STATE / 'state.json'))
    if camera_info['device'].get('device_model') != 'TC70' or camera_info['device'].get('hw_version', '').split('.')[0] != '5':
        raise ValueError('Unsupported continuous camera')
    status = json.loads((STATE / 'continuous-status.json').read_text())
    if status.get('state') != 'awaiting_pairing' or time.time() - status['checked_at'] > 15:
        raise ValueError('Continuous recording service is not waiting for pairing')
    ready = False
    for index in (STORE / 'events').glob('event-*.mp4.json'):
        if index.is_symlink():
            continue
        item = json.loads(index.read_text())
        path = Path(str(index)[:-5])
        if (item.get('camera_mac') == mac and item.get('event_type') == 'continuous'
                and item.get('validated_recording') is True and item.get('duration', 0) >= 20
                and 0 <= time.time() - item.get('source_time', 0) < 1200
                and path.is_file() and not path.is_symlink() and path.stat().st_size == item.get('bytes')):
            ready = True
            break
    if not ready:
        raise ValueError('No recent validated continuous recording')
    password = json.loads((STATE / 'state.json').read_text())['password_hash']
    camera = CameraProbe(camera_info['address'], password, timeout=10)
    camera.login()
    before = camera._batch('getRecordPlan', {'record_plan': {'name': ['chn1_channel']}})
    if before.get('error_code') != 0:
        raise ValueError('Cannot preserve TC70 schedule')
    baseline = STATE / 'tc70-pre-bind.json'
    if not baseline.exists():
        atomic_json(baseline, {'record_plan': before, 'hub_storage': camera.read('getHubStorage')})
    hub_mac = normalize_mac(Path('/sys/class/net/eth0/address').read_text().strip())
    response = camera._batch('setBindHubConfig', {'hub_manage': {'hub_config_set': {'hub_storage': {
        'storage_enabled': 'on', 'storage_mac': hub_mac.replace(':', '').upper(),
        'ipaddr': '10.23.0.72', 'hub_password_list': [{'password': password, 'encrypt_type': '3'}]}}}})
    if response.get('error_code') != 0:
        raise ValueError('TC70 did not accept hub selection')
    for _ in range(12):
        enrolled = json.loads((STATE / 'enrolled.json').read_text()).get(mac, {})
        if enrolled.get('hub_storage_enabled'):
            after = camera._batch('getRecordPlan', {'record_plan': {'name': ['chn1_channel']}})
            print(json.dumps({'native_registration': True, 'schedule_unchanged': before == after,
                              'automatic_unlink': False}))
            return
        time.sleep(1)
    raise ValueError('TC70 accepted selection; native registration is not yet confirmed')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'status': 'binding_not_confirmed'}))
        raise SystemExit(1)
