"""Passively wait for the first C400 event and verify hub playback; no camera requests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from camera_media import STORE
from recording_playback import DETECTION_ALARMS

RESULT = Path('/var/lib/tapo-hub/c400-first-event-check.json')
ENROLLED = Path('/var/lib/tapo-hub/enrolled.json')


def report(state, **details):
    temporary = RESULT.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'state': state, 'checked_at': time.time(), **details}, stream)
    os.replace(temporary, RESULT)
    print(json.dumps({'state': state, **details}), flush=True)


def main():
    enrolled = json.loads(ENROLLED.read_text())
    mac = next(mac for mac, record in enrolled.items() if record['device_model'] == 'C400' and record.get('hub_storage_enabled'))
    report('waiting_for_native_event')
    deadline = time.monotonic()+24*60*60
    videos = []
    while time.monotonic() < deadline:
        videos = []
        for index in (STORE/'events').glob('event-*.mp4.json'):
            try:
                details = json.loads(index.read_text())
                if details.get('camera_mac') == mac and details.get('validated_recording') is True:
                    videos.append((details.get('source_time', 0), index, details))
            except (OSError, ValueError):
                continue
        if videos:
            stamp, index, details = min(videos, key=lambda item: item[0])
            if details.get('event_type') not in DETECTION_ALARMS:
                report('event_metadata_needs_review', video_available=True)
                return
            image = index.with_suffix('').with_suffix('.jpg')
            if image.is_file() and Path(str(image)+'.json').is_file():
                try:
                    result = subprocess.run([sys.executable, str(Path(__file__).with_name('check_tapo_playback.py')), '--model', 'C400'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
                    report('passed' if result.returncode == 0 else 'playback_needs_review',
                           returncode=result.returncode, source_time=stamp, video_available=True, thumbnail_available=True)
                except subprocess.TimeoutExpired:
                    report('playback_check_timed_out', video_available=True, thumbnail_available=True)
                return
        failures = list((STORE/'failed-uploads'/'c400').glob('*.wire.json'))
        if failures and not videos:
            report('native_upload_needs_review', retained_diagnostic_count=len(failures), video_available=False)
            return
        time.sleep(5)
    report('no_event_observed', video_available=bool(videos))


if __name__ == '__main__':
    main()
