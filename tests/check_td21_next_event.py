"""Verify a new TD21 upload, exact-clip playback and face analysis without waking cameras."""
import argparse
import http.client
import re
import json
from pathlib import Path
import subprocess
import sys
import time

from camera_media import STORE
from camera_probe import CameraProbe
from continuous_recording import atomic_json
from recording_retention import activity

ROOT = Path('/var/lib/tapo-hub')
RESULT = ROOT / 'td21-next-event-check.json'


def inspect_recordings(mac, after):
    rows = []
    for index in (STORE / 'events').glob('event-*.mp4.json'):
        try:
            if index.is_symlink() or index.stat().st_size > 2_000_000:
                continue
            data = json.loads(index.read_text())
            media = Path(str(index)[:-5])
            if not re.fullmatch(r'event-[0-9a-f]{24}', media.stem):
                continue
            if (data.get('camera_mac') == mac and data.get('validated_recording') is True
                    and data.get('recovered_partial') is not True
                    and data.get('format_version') == 1 and type(data.get('source_time')) is int
                    and data['source_time'] >= after and media.is_file() and not media.is_symlink()
                    and media.stat().st_size == data['bytes']):
                rows.append((data['source_time'], media, data.get('event_type')))
        except (OSError, ValueError, TypeError, KeyError):
            continue
    return sorted(rows)


def recent_failures(mac, after):
    failures = 0
    for index in (STORE / 'failed-uploads' / 'td21').glob('*.wire.json'):
        try:
            if index.is_symlink() or index.stat().st_size > 2_000_000:
                continue
            data = json.loads(index.read_text())
            if data.get('camera_mac') == mac and data.get('captured_at', 0) >= after:
                failures += 1
        except (OSError, ValueError, TypeError):
            continue
    return failures


def face_status(mac, key):
    password = json.loads((ROOT / 'state.json').read_text())['password_hash']
    client = CameraProbe('10.23.0.72', password)
    client.login()
    response = client._request({'method': 'getLocalFaceAnalysisStatus', 'params': {'face_detection': {
        'analysis_status': {'camera_mac': mac, 'file_id': key}}}})
    if response.get('error_code') != 0:
        raise ValueError('Face status unavailable')
    return response['result']['face_detection']['analysis_status']


def run(after, seconds=86400):
    previous = json.loads(RESULT.read_text()) if RESULT.exists() else {}
    if previous.get('after') == after and previous.get('state') == 'passed':
        return
    started = previous.get('started_at', time.time()) if previous.get('after') == after else time.time()
    deadline = time.monotonic() + max(0, seconds - (time.time() - started))
    devices = json.loads((ROOT / 'enrolled.json').read_text())
    mac, = [mac for mac, record in devices.items()
            if record.get('device_model') == 'TD21' and record.get('hub_storage_enabled')]
    details = {}
    def report(state, **extra):
        atomic_json(RESULT, {'state': state, 'started_at': started, 'after': after,
                            'checked_at': time.time(), **details, **extra})
    report('waiting_for_native_event')
    first_seen = None
    checked = None
    while time.monotonic() < deadline:
        try:
            with activity():
                rows = inspect_recordings(mac, after)
                failures = recent_failures(mac, after)
            if not rows:
                report('upload_failed_waiting_retry' if failures else 'waiting_for_native_event',
                       recent_failure_count=failures)
                time.sleep(5)
                continue
            stamp, media, event_type = rows[0]
            details.update(source_time=stamp, file_id=media.stem, video_available=True)
            if first_seen is None:
                first_seen = time.monotonic()
            if event_type not in ('MD', 'PD'):
                report('event_metadata_needs_review')
                return
            image, index = media.with_suffix('.jpg'), media.with_suffix('.jpg.json')
            thumbnail = all(path.is_file() and not path.is_symlink() for path in (image, index))
            if not thumbnail:
                report('waiting_for_thumbnail')
                if time.monotonic() - first_seen > 120:
                    report('thumbnail_missing')
                    return
            else:
                if checked != media.stem:
                    report('checking_playback', thumbnail_available=True)
                    outcome = subprocess.run([sys.executable, str(Path(__file__).with_name('check_tapo_playback.py')),
                        '--model', 'TD21', '--file-id', media.stem], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=180)
                    if outcome.returncode:
                        report('playback_needs_review', returncode=outcome.returncode)
                        return
                    checked = media.stem
                    details.update(encrypted_playback='passed', thumbnail_available=True)
                status = face_status(mac, media.stem)
                if status['analyzed'] is True and status['state'] == 'complete':
                    report('passed', face_analysis_complete=True,
                           **{key: status[key] for key in ('face_count', 'familiar_count', 'stranger_count')})
                    return
                if status['state'] == 'disabled':
                    report('face_analysis_disabled')
                    return
                report('waiting_for_face_analysis', face_state=status['state'])
                if time.monotonic() - first_seen > 900:
                    report('face_analysis_needs_review')
                    return
        except subprocess.TimeoutExpired:
            report('playback_check_timed_out')
            return
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            if checked is not None and first_seen is not None and time.monotonic() - first_seen > 900:
                report('face_analysis_needs_review')
                return
            report('check_deferred')
        time.sleep(5)
    report('observation_ended_without_verification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after', type=int, required=True, help='Earliest event UTC epoch to accept')
    arguments = parser.parse_args()
    if not 0 < arguments.after <= time.time():
        parser.error('--after must be a past UTC timestamp')
    run(arguments.after)
