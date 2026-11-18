#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run inside the dedicated LXC as root.' >&2; exit 1; }
systemd-detect-virt --container >/dev/null || { echo 'Refusing installation on a Proxmox host or non-container system.' >&2; exit 1; }
uv_binary=$(command -v uv || true)
uv_binary="${uv_binary:-/usr/local/bin/uv}"
[[ -x "$uv_binary" ]] || { echo 'Install uv using the community-scripts setup_uv helper first.' >&2; exit 1; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ "$PWD" == /opt/tapo-hub ]] || { echo 'Install the release in /opt/tapo-hub first.' >&2; exit 1; }
"$uv_binary" venv --allow-existing --python /usr/bin/python3 .venv
"$uv_binary" pip install --python .venv/bin/python --require-hashes -r requirements.lock
.venv/bin/python app/install_services.py
printf '%s\n' 'Tapo Hub and local AI are installed but not advertising yet.' \
  'Attach an empty dedicated recording volume, then run: tapo-hub configure' \
  'Discovery and pairing guide: tapo-hub guide'
