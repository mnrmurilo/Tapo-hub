"""Explicit recovery of intact multipart frames; originals remain unchanged."""
import argparse
import io
import json
from pathlib import Path
import re
import tempfile

from camera_media import STORE, headers
from camera_registry import normalize_mac, camera_supported
from native_recordings import save_event
from recording_retention import activity


def complete_prefix(data, content_type):
    match = re.fullmatch(r'multipart/x-mixed-replace;\s*boundary="?([A-Za-z0-9_-]{1,64})"?', content_type)
    if not match or len(data) > 20_000_000:
        raise ValueError("Invalid native fragment")
    boundary = b"--" + match[1].encode()
    stream = io.BytesIO(data)
    end = 0
    while stream.tell() < len(data):
        line = stream.readline(129)
        if line == b"\r\n":
            continue
        if line != boundary + b"\r\n":
            break
        try:
            part = headers(stream)
            length = int(part.get("content-length", "-1"))
        except (ValueError, OSError):
            break
        if not 0 < length <= 2_000_000 or len(stream.read(length)) != length:
            break
        end = stream.tell()
    if not end:
        raise ValueError("No intact native frames")
    return data[:end]


def recover(index):
    index = Path(index)
    if (not index.resolve().is_relative_to(STORE.resolve()) or index.is_symlink()
            or index.stat().st_size > 2_000_000 or not index.name.endswith('.wire.json')):
        raise ValueError("Unsafe fragment metadata")
    wire = Path(str(index)[:-5])
    if wire.is_symlink() or not 0 < wire.stat().st_size <= 20_000_000:
        raise ValueError("Unsafe fragment media")
    metadata = json.loads(index.read_text())
    if metadata.get('endpoint') != '/stream/alarm_streaming' or metadata.get('transfer_complete') is not False:
        raise ValueError("Expected a retained incomplete video")
    mac = normalize_mac(metadata['camera_mac'])
    enrolled = json.loads(Path('/var/lib/tapo-hub/enrolled.json').read_text())
    if (mac not in enrolled or enrolled[mac].get('device_model') not in ('TD21', 'C400')
            or not camera_supported(enrolled[mac])):
        raise ValueError("Expected a supported registered battery camera fragment")
    if not re.fullmatch(r'[0-9]{1,20}', metadata['event_id']):
        raise ValueError("Invalid source event")
    state = json.loads(Path('/var/lib/tapo-hub/state.json').read_text())
    with activity(exclusive=True), tempfile.TemporaryDirectory(dir=STORE, prefix='.partial-recovery-') as work:
        body = Path(work) / 'intact.wire'
        body.write_bytes(complete_prefix(wire.read_bytes(), metadata['content_type']))
        result = save_event(body, metadata, state['password_hash'], mac, recovered_partial=True)
    saved = json.loads(Path(result['path'] + '.json').read_text())
    return {'source_time': saved['source_time'], 'file_id': Path(result['path']).stem,
            'duration': round(len(saved['video_pts']) / saved['rate'], 2),
            'recovered_partial': saved.get('recovered_partial', False), 'duplicate': result['duplicate']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('metadata', type=Path, nargs='+', help='Retained .wire.json files to recover explicitly')
    for index in parser.parse_args().metadata:
        print(json.dumps(recover(index)), flush=True)
