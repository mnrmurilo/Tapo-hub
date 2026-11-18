"""TC70 continuous LAN recorder; camera recording settings are never written here."""
import argparse
import csv
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import select
import signal
import shutil
import stat
import subprocess
import tempfile
import threading
import time

from camera_media import STORE, preview_packets
from camera_probe import probe
from camera_registry import normalize_mac
from continuous_audio import AudioPES
from native_recordings import run_media
from recording_retention import activity, check_store, free_bytes, LOW_FREE

STATE = Path('/var/lib/tapo-hub')


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.continuous-')
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def publish(path, mac, source_time):
    """A closed, decoded segment becomes visible only after its atomic index commit."""
    mac = normalize_mac(mac)
    run_media(['-xerror', '-i', str(path), '-f', 'null', '-'])
    details = json.loads(subprocess.check_output([
        'ffprobe', '-v', 'error', '-show_entries',
        'format=duration:stream=codec_type,codec_name,width,height,sample_rate',
        '-of', 'json', str(path)], timeout=15))
    duration = float(details['format']['duration'])
    tracks = details['streams']
    if (not math.isfinite(duration) or not 0 < duration <= 125
            or not any(t.get('codec_type') == 'video' and t.get('codec_name') == 'h264' for t in tracks)
            or not any(t.get('codec_type') == 'audio' and t.get('codec_name') == 'aac' for t in tracks)):
        raise ValueError('Continuous segment lost a required track')
    event_id = str(round(source_time * 1_000_000))
    stem = 'event-' + hashlib.sha256((mac + ':' + event_id).encode()).hexdigest()[:24]
    image = path.with_suffix('.jpg')
    run_media(['-i', str(path), '-frames:v', '1', '-q:v', '3', str(image)])
    report = {'camera_mac': mac, 'event_id': event_id, 'format_version': 1,
              'event_type': 'continuous', 'source_time': int(source_time),
              'source_time_precise': source_time,
              'duration': duration, 'verified_tracks': tracks}
    with activity():
        directory = STORE / 'events'
        directory.mkdir(mode=0o700, exist_ok=True)
        for source, kind in ((image, 'jpg'), (path, 'mp4')):
            destination = directory / (stem + '.' + kind)
            metadata = {**report, 'format': kind, 'validated_recording': kind == 'mp4',
                        'bytes': source.stat().st_size}
            os.chmod(source, 0o600)
            with source.open('rb') as stream:
                os.fsync(stream.fileno())
            os.replace(source, destination)
            atomic_json(destination.with_suffix('.' + kind + '.json'), metadata)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return {'source_time': int(source_time), 'duration': duration}


def write_pipe(descriptor, data):
    view = memoryview(data)
    while view:
        if not select.select([], [descriptor], [], 5)[1]:
            raise TimeoutError('Continuous muxer stopped reading')
        try:
            size = os.write(descriptor, view)
        except BlockingIOError:
            continue
        view = view[size:]


def record_session(address, password_hash, mac, **options):
    check_store()
    if free_bytes() < LOW_FREE:
        raise ValueError('Continuous recording paused for retention')
    descriptor = os.open(STORE / '.continuous.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_dev != STORE.stat().st_dev:
            raise ValueError('Unsafe continuous recording lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for abandoned in STORE.glob('.continuous-*'):
            info = abandoned.lstat()
            if (not abandoned.is_symlink() and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == os.geteuid() and info.st_dev == STORE.stat().st_dev):
                shutil.rmtree(abandoned)
        return _record_session(address, password_hash, mac, **options)
    finally:
        os.close(descriptor)


def _record_session(address, password_hash, mac, *, seconds=None, segment_seconds=30, progress=None, keep_recording=None):
    """Keep one preview connection across segment boundaries; fail closed on missing storage."""
    if not 5 <= segment_seconds <= 60:
        raise ValueError('Invalid continuous segment length')
    check_store()
    if free_bytes() < LOW_FREE:
        raise ValueError('Continuous recording paused for retention')
    os.umask(0o077)
    # Active files stay outside retention's canonical groups and are bounded per session.
    with tempfile.TemporaryDirectory(dir=STORE, prefix='.continuous-') as work:
        work = Path(work)
        read_audio, write_audio = os.pipe()
        os.set_blocking(write_audio, False)
        errors, sound, video = [], queue.Queue(maxsize=128), queue.Queue(maxsize=16)
        stop = threading.Event()
        def pipe_writer(descriptor, incoming):
            try:
                while not stop.is_set():
                    try:
                        data = incoming.get(timeout=.2)
                    except queue.Empty:
                        continue
                    if data is None:
                        break
                    write_pipe(descriptor, data)
            except (OSError, ValueError) as error:
                errors.append(type(error).__name__)
            finally:
                os.close(descriptor)
        process = None
        packets = preview_packets(address, password_hash)
        threads = []
        completed, anchor = set(), None
        segment_list = work / 'segments.csv'
        def closed_segments():
            if not segment_list.exists():
                return
            text = segment_list.read_text()
            for row in csv.reader(text[:text.rfind('\n') + 1].splitlines()):
                if len(row) != 3 or row[0] in completed:
                    continue
                name, start, end = row
                if Path(name).name != name or not name.startswith('part-') or not name.endswith('.mp4'):
                    raise ValueError('Invalid segment list')
                start, end = float(start), float(end)
                if not 0 <= start < end or end - start > 125:
                    raise ValueError('Invalid segment timing')
                result = publish(work / name, mac, anchor + start)
                completed.add(name)
                if len(completed) > 32:
                    completed.remove(min(completed))
                if progress:
                    progress(result)
        try:
            process = subprocess.Popen([
                'ffmpeg', '-v', 'error', '-nostdin', '-thread_queue_size', '32',
                '-probesize', '32768', '-analyzeduration', '1000000', '-f', 'mpegts', '-i', 'pipe:0',
                '-thread_queue_size', '32', '-probesize', '32', '-analyzeduration', '1',
                '-f', 'mulaw', '-ar', '16000', '-ac', '1',
                '-i', 'pipe:' + str(read_audio), '-map', '0:v:0', '-map', '1:a:0',
                '-c:v', 'copy', '-c:a', 'aac', '-b:a', '32k',
                '-f', 'segment', '-segment_time', str(segment_seconds), '-reset_timestamps', '1',
                '-segment_format', 'mp4', '-segment_format_options', 'movflags=+faststart',
                '-segment_list_type', 'csv', '-segment_list_size', '4',
                '-segment_list', str(segment_list), 'part-%09d.mp4'],
                cwd=work, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, pass_fds=(read_audio,))
            os.close(read_audio)
            read_audio = None
            os.set_blocking(process.stdin.fileno(), False)
            video_fd = os.dup(process.stdin.fileno())
            process.stdin.close()
            for descriptor, incoming in ((write_audio, sound), (video_fd, video)):
                thread = threading.Thread(target=pipe_writer, args=(descriptor, incoming), daemon=True)
                thread.start()
                threads.append(thread)
            audio = AudioPES()
            began = time.monotonic()
            failure = None
            try:
                for data in packets:
                    if anchor is None:
                        anchor = time.time()
                    check_store()
                    if free_bytes() < 100_000_000 or errors or process.poll() is not None:
                        raise ValueError('Continuous recording interrupted')
                    for chunk in audio.feed(data):
                        sound.put(chunk, timeout=5)
                    video.put(data, timeout=5)
                    closed_segments()
                    if sum(p.stat().st_size for p in work.glob('part-*.mp4')) > 40_000_000:
                        raise ValueError('Unpublished continuous data exceeded limit')
                    if seconds is not None and time.monotonic() - began >= seconds:
                        break
                    if keep_recording is not None and not keep_recording():
                        break
            except (OSError, ValueError, subprocess.SubprocessError, queue.Full) as error:
                failure = error
            # Even a failed camera connection can have a valid tail buffered in the muxer.
            video.put(None, timeout=5)
            sound.put(None, timeout=5)
            for thread in threads:
                thread.join(timeout=10)
            if any(thread.is_alive() for thread in threads) or errors:
                raise ValueError('Continuous muxer did not finish cleanly')
            result = process.wait(timeout=15)
            closed_segments()
            if failure is not None:
                raise failure
            if result != 0:
                raise ValueError('Continuous muxer did not finish cleanly')
            return {'segments': len(completed)}
        finally:
            packets.close()
            stop.set()
            if process is not None:
                if not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            for thread in threads:
                thread.join(timeout=6)
            if not threads:
                os.close(write_audio)
            if read_audio is not None:
                os.close(read_audio)


def watch(mac):
    mac = normalize_mac(mac)
    delay = 5
    status = STATE / 'continuous-status.json'
    stopping = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopping.set())
    def enabled():
        return (not stopping.is_set() and
                json.loads((STATE / 'enrolled.json').read_text()).get(mac, {}).get('hub_storage_enabled') is True
                and json.loads((STATE / 'cameras.json').read_text())['devices'].get(mac, {}).get('continuous') is True)
    while not stopping.is_set():
        try:
            if not enabled():
                atomic_json(status, {'state': 'awaiting_pairing', 'checked_at': time.time()})
                stopping.wait(5)
                continue
            camera = probe(mac, str(STATE / 'cameras.json'), str(STATE / 'state.json'))
            if camera['device'].get('device_model') != 'TC70' or camera['device'].get('hw_version', '').split('.')[0] != '5':
                raise ValueError('Continuous recording is limited to TC70')
            password_hash = json.loads((STATE / 'state.json').read_text())['password_hash']
            atomic_json(status, {'state': 'connecting', 'checked_at': time.time()})
            def progress(result):
                nonlocal delay
                delay = 5
                atomic_json(status, {'state': 'recording', 'checked_at': time.time(), **result})
            record_session(camera['address'], password_hash, mac, progress=progress, keep_recording=enabled)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, queue.Full):
            atomic_json(status, {'state': 'reconnecting', 'checked_at': time.time()})
        stopping.wait(delay)
        delay = min(delay * 2, 60)
    atomic_json(status, {'state': 'stopped', 'checked_at': time.time()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mac', required=True)
    watch(parser.parse_args().mac)
