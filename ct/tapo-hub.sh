#!/usr/bin/env bash
_CS_DEFAULT_URL="https://raw.githubusercontent.com/mnrmurilo/Tapo-hub/main"
_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../core}/core/build.func"
source "$_cs_boot" 2>/dev/null || source <(curl -fsSL "${COMMUNITY_SCRIPTS_CORE_URL:-https://raw.githubusercontent.com/community-scripts/core/main}/core/build.func")
# License: MIT
# Application source; override var_repository to use a compatible fork.
APP="Tapo Hub"
var_tags="${var_tags:-camera;nvr;local-ai}"
var_cpu="${var_cpu:-2}"
var_ram="${var_ram:-2048}"
var_disk="${var_disk:-8}"
var_os="${var_os:-debian}"
var_version="${var_version:-13}"
var_arm64="${var_arm64:-no}"
var_unprivileged="${var_unprivileged:-1}"

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources
  if [[ ! -f /etc/tapo-hub/source.json ]]; then
    msg_error "No Tapo Hub release installation found"
    exit 1
  fi
  var_repository=$(python3 -c 'import json; print(json.load(open("/etc/tapo-hub/source.json"))["repository"])')
  if check_for_gh_release "tapo-hub" "$var_repository"; then
    trap 'systemctl start tapo-hub-face tapo-hub' EXIT
    msg_info "Stopping Tapo Hub"
    systemctl stop tapo-hub tapo-hub-face
    msg_ok "Stopped Tapo Hub"
    create_backup /etc/tapo-hub
    CLEAN_INSTALL=1 CLEAN_INSTALL_KEEP=".venv" fetch_and_deploy_gh_release "tapo-hub" "$var_repository" "tarball"
    restore_backup
    msg_info "Updating Tapo Hub and local AI dependencies"
    cd /opt/tapo-hub
    $STD uv pip install --python .venv/bin/python --require-hashes -r requirements.lock
    $STD /opt/tapo-hub/.venv/bin/python app/install_services.py
    msg_ok "Updated Tapo Hub and local AI dependencies"
    msg_info "Starting Tapo Hub"
    systemctl start tapo-hub-face tapo-hub
    systemctl start 'tapo-hub-continuous@*.service' || true
    msg_ok "Started Tapo Hub"
    trap - EXIT
  fi
  exit
}

var_repository="${var_repository:-mnrmurilo/Tapo-hub}"
[[ "$var_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { msg_error "Enter a published Tapo Hub source repository before creating an LXC"; exit 1; }
export var_repository var_recording_storage var_recording_gb var_setup_json
start
build_container
description

msg_info "Selecting Tapo Hub recording storage"
pvesm status -content rootdir
var_recording_storage=$(prompt_input_required "Proxmox storage pool for a NEW dedicated recording volume:" "${CONTAINER_STORAGE:-}" 120 "var_recording_storage")
var_recording_gb=$(prompt_input_required "Recording volume size in GiB:" "100" 120 "var_recording_gb")
[[ "$var_recording_storage" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ && "$var_recording_gb" =~ ^[1-9][0-9]{0,4}$ ]] || { msg_error "Invalid recording storage or size"; exit 1; }
[[ $var_recording_gb -ge 4 ]] || { msg_error "Select at least 4 GiB for recordings"; exit 1; }
if pct config "$CTID" | grep -q '^mp0:'; then
  msg_error "Mount point mp0 is already configured; existing storage will not be replaced"
  exit 1
fi
pvesm status -storage "$var_recording_storage" -content rootdir | grep -q 'active' || { msg_error "Selected recording storage is unavailable"; exit 1; }
validate_storage_space "$var_recording_storage" "$var_recording_gb" "yes"
pct set "$CTID" --mp0 "${var_recording_storage}:${var_recording_gb},mp=/var/lib/tapo-hub/recordings,backup=1"
pct reboot "$CTID"
deadline=$((SECONDS + 120))
until pct exec "$CTID" -- mountpoint -q /var/lib/tapo-hub/recordings; do
  [[ $SECONDS -lt $deadline ]] || { msg_error "Recording volume did not mount. Keep the LXC and inspect its mount point before running tapo-hub configure"; exit 1; }
  sleep 2
done
msg_ok "Created Tapo Hub dedicated recording volume"
msg_info "Configuring Tapo Hub discovery, cameras and local AI"
if [[ -n "${var_setup_json:-}" ]]; then
  pct exec "$CTID" -- python3 -c 'import json,os,sys; data=json.loads(sys.argv[1]); fd=os.open("/etc/tapo-hub/setup-input.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,json.dumps(data).encode()); os.close(fd)' "$var_setup_json"
  pct exec "$CTID" -- /usr/local/bin/tapo-hub configure --config-file /etc/tapo-hub/setup-input.json --models later
  pct exec "$CTID" -- rm /etc/tapo-hub/setup-input.json
else
  pct exec "$CTID" -- /usr/local/bin/tapo-hub configure
fi
msg_ok "Configured Tapo Hub discovery, cameras and local AI"
msg_ok "Completed successfully!\n"
echo -e "${INFO}${YW}In Tapo choose Add Device -> H500 -> Ethernet/wired. Run tapo-hub guide in the LXC for the full walkthrough.${CL}"
