"""Reject runtime artifacts and embedded credentials in the source export."""
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
for path in root.rglob('*'):
    if any(part in ('.git', '.venv', '__pycache__') for part in path.relative_to(root).parts):
        continue
    if path.is_symlink():
        raise SystemExit(f'Release symlink requires review: {path.relative_to(root)}')
    if not path.is_file():
        continue
    if any(path.name.endswith(suffix) for suffix in ('.pem', '.key', '.onnx', '.duckdb', '.wal', '.pcap', '.wire', '.mp4', '.jpg', '.heic')):
        raise SystemExit(f'Runtime/binary artifact in release: {path.relative_to(root)}')
    if path.name in ('config.json', 'cameras.json', 'enrolled.json', 'state.json'):
        raise SystemExit(f'Runtime configuration in release: {path.relative_to(root)}')
    data = path.read_text()
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', data):
        raise SystemExit(f'Private key in release: {path.relative_to(root)}')
    if re.search(r'(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}', data):
        raise SystemExit(f'GitHub token in release: {path.relative_to(root)}')
print('Source artifact and credential scan passed')
