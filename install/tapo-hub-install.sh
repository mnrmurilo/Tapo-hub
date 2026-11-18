#!/usr/bin/env bash
# License: MIT
source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

msg_info "Installing Tapo Hub dependencies"
$STD apt install -y nftables libglib2.0-0
msg_ok "Installed Tapo Hub dependencies"
PYTHON_VERSION="3.13" setup_uv
setup_ffmpeg
var_repository="${var_repository:-mnrmurilo/Tapo-hub}"
[[ "$var_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { msg_error "Tapo Hub source repository is required"; exit 1; }
fetch_and_deploy_gh_release "tapo-hub" "$var_repository" "tarball"
msg_info "Installing Tapo Hub and local face recognition"
cd /opt/tapo-hub
$STD uv venv --python /usr/bin/python3 .venv
$STD uv pip install --python .venv/bin/python --require-hashes -r requirements.lock
$STD .venv/bin/python app/install_services.py
mkdir -p /etc/tapo-hub
printf '{"repository":"%s"}\n' "$var_repository" >/etc/tapo-hub/source.json
chmod 0600 /etc/tapo-hub/source.json
msg_ok "Installed Tapo Hub and local face recognition"
motd_ssh
customize
cleanup_lxc
