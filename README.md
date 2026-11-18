# Tapo Hub

An experimental local camera hub for a dedicated Proxmox LXC. It emulates the
tested H500 discovery, camera storage and playback APIs used by the Tapo app.
Recordings are served **phone → hub → stored footage**, with local YuNet/ArcFace
face recognition and a private DuckDB face registry.

This is independent software, not TP-Link firmware or an official H500 replacement.
Automatic recording works on tested devices but interrupted battery-camera uploads
remain a reliability limitation. Retain an independent recording option where needed.

## What is included

- Local H500 discovery, pairing, disk status, event lists, thumbnails and encrypted playback.
- MAC-keyed allowlist: users supply the cameras the hub may discover. No personal camera inventory is included.
- TD21 events, C400 hardware 2.x events and TC70 hardware 5.x support; TC70 continuous recording is optional.
- Local face detection/recognition, familiar/unknown profiles, photo enrollment, editing,
  combining and links back to saved event footage in Tapo.
- Dedicated recording storage, oldest-first retention and explicit validated fragment recovery.
- Health checks and a guided discovery/pairing walkthrough.

Native Tapo face push notifications, built-in Wi-Fi fallback and complete H500 feature
parity are **not implemented**.

## Requirements

- Proxmox VE with an **unprivileged Debian 13 amd64 LXC** on the cameras' IPv4 LAN.
- Recommended starting resources: 2 CPU cores, 2 GiB RAM and 8 GiB root disk.
- A separate recording volume; the helper asks for its **Proxmox storage pool and size**.
  The default is 100 GiB and the minimum is 4 GiB. Root-disk selection and recording
  storage selection are separate choices.
- LAN reachability among phone, hub and cameras. Broadcast discovery must cross the
  selected bridge; Wi-Fi client isolation prevents discovery. A routed VPN alone
  does not necessarily carry discovery broadcasts.
- Internet during package/model installation. Runtime hub egress is restricted to the
  configured LAN. This does not prove the phone/cameras themselves are cloud-independent.

Python environments and dependencies are managed with **Astral uv**. The helper uses
`setup_uv`, creates `.venv` with `uv venv`, and installs the hash-locked dependencies
with `uv pip install --require-hashes`. Updates and CI use the same environment.

## Install with the Proxmox helper

Source: [mnrmurilo/Tapo-hub](https://github.com/mnrmurilo/Tapo-hub).
The helper requires a **tagged GitHub release**, which is not available yet.
A source checkout alone is not sufficient for the release-based installer.

Once a GitHub release exists, run `ct/tapo-hub.sh` from the Proxmox host. It uses the
community-scripts shared engine and defaults to `mnrmurilo/Tapo-hub` as its application
source; `var_repository` can select a compatible fork. The full one-command host
workflow still needs clean-host validation before it is recommended.
New community-scripts submissions go through **DevScripts** before promotion to
ProxmoxVE: https://github.com/community-scripts/DevScripts . Inclusion is controlled
by that project's maintainers and is not implied by having a compatible helper.

The guided sequence is:

1. Choose LXC resources, network and root storage using the standard helper wizard.
2. Choose a Proxmox storage pool and size for a **new dedicated recording volume**.
   No existing disk is formatted or adopted. Existing `mp0` is never overwritten.
3. Confirm the hub IP, LAN subnet and timezone. Reserve the IP in DHCP.
4. Enter up to three allowed cameras: **model, hardware version, MAC and current IP**.
   Find the MAC/hardware version in Tapo → camera → Device Info. IP is an initial
   hint; MAC remains the inventory key as addresses change. Other cameras are ignored.
   You can leave the list empty to set up the hub first and add cameras later.
5. Choose the local recognition model source, then run the hub health checks.
6. Follow the Tapo discovery walkthrough below. Pairing is not proof of a saved video.

Setup can be resumed in the LXC with `tapo-hub configure`. For unattended setup use
`--config-file /path/to/private.json`; see [configuration](docs/configuration.md).
No Tapo account password is requested by the installer or stored in this repository.

## Choose local AI models

The local AI engine and its Python dependencies are installed together with the hub.
Recognition becomes available only after valid models load successfully.

| Setup option | What it does |
|---|---|
| Download tested ArcFace buffalo_sc | Fetches checksum-pinned YuNet and compact 512-dimensional ArcFace weights after explicit model-terms acknowledgement. |
| Use a licensed ONNX file | Accepts a user-supplied compatible ArcFace model with 112×112 RGB input, the existing normalization/alignment and 512 output values. Its content hash identifies the model, preventing cross-model matching. |
| Set up models later | Installs the hub and inference dependencies; does not claim recognition is ready. Run configuration again when models are available. |

**Model weights have their own usage terms.** InsightFace's pretrained model terms
specify non-commercial research use; the library's MIT license does not cover the
weights. Review https://github.com/deepinsight/insightface/tree/master/python-package#license
and use weights you are authorized to use. No ONNX weights are bundled in the repository.
The installer validates file hashes and network shape. Recognition runs locally;
face images and embeddings are not uploaded for inference. New/different model
families need separate compatibility and identity-accuracy testing.

To finish deferred model setup without re-entering the camera list:

```sh
tapo-hub models --models file --model-path /root/recognition.onnx
```

For the tested download, use `tapo-hub models --models download --accept-model-terms`
only after reviewing the upstream terms. A successful download does not grant a model license.

## Discover and add the hub in Tapo

1. Run **`tapo-hub doctor`** in the LXC. Confirm storage, local discovery, encrypted
   control and, if configured, local face-AI readiness.
2. Connect the phone to the same LAN as the LXC. On iOS allow Tapo **Local Network**
   permission. Check guest-Wi-Fi isolation and VLAN/broadcast rules.
3. In Tapo choose **+ → Add Device → Hubs → H500 → Ethernet/wired setup**.
4. Add the discovered hub. Then open **Add Existing Device**, select one configured
   camera and connect it. A sleeping TD21/C400 may need its live view opened briefly
   before refreshing this list. Do not leave live view running to test event recording.
5. Let a real event occur. Open **H500 → Playback → camera → correct date**.
   Confirm an event entry, thumbnail and playable video from the server.
6. Open **Face Recognition**, add a clear familiar profile, and verify real familiar
   and unknown results. A completed analysis with zero faces is valid; a gallery
   entry alone does not establish identification accuracy.

Repeat the guide with `tapo-hub guide`. Cameras should remain configured for their
existing recording needs until hub reception has been verified in the intended conditions.

## Storage, data and recovery

Configuration is under `/etc/tapo-hub`; private association state is under
`/var/lib/tapo-hub`. The recording volume must be mounted at
`/var/lib/tapo-hub/recordings`. Setup refuses the container root filesystem and an
unmarked volume that contains other application data. It never runs a format command.
The helper allocates a new Proxmox-managed volume instead of reusing an arbitrary
host directory. Keep photo libraries and other applications on separate mounts.

MP4/JPEG files and recording indexes remain ordinary files. Face profiles, embeddings,
appearances and notification preferences use DuckDB; no separate database server is needed.
Only the hub process opens the live face database. Configuration/index JSON is not a
second database engine. Stop the hub before copying DuckDB and its WAL for a backup,
or use a consistent Proxmox backup that includes the dedicated recording volume.

The receiver preserves bounded failure evidence. `recover_native_partial.py` can
explicitly publish only the intact, codec-validated portion of a retained battery-camera
upload. These clips retain incomplete-transfer metadata and short actual playback
durations. Missing seconds cannot be reconstructed. Fragment recovery is manual,
not an automatic full-recording guarantee; a native Tapo card has no custom partial label.

## Troubleshooting

| Symptom | First checks |
|---|---|
| Hub not found | `tapo-hub doctor`; correct bridge/subnet; phone Local Network permission; Wi-Fi client isolation; UDP 20002/20015. |
| Camera missing or “not same network” | Configured MAC/IP/model/hardware; wake a battery camera and refresh; check DHCP changes. |
| Pairing succeeds but no footage | Check native upload logs, event date/timezone and storage. Snapshots can arrive even if video transfer fails. |
| Video reports unstable network | Check the hub journal and completed media, not only Wi-Fi signal. Protocol and upload failures can share this message. |
| Local AI unavailable | Verify models were installed, hashes match and `tapo-hub-face` is healthy. |
| Notifications toggle fails | Native face-event push delivery is not implemented; no substitute success state is returned. |
| Two temporary hub cards | A client-cache/metadata issue is under investigation. The exact cause is unconfirmed; compare device identities before changing associations. |

Useful commands: `tapo-hub status`, `tapo-hub doctor`, `journalctl -u tapo-hub`,
and `journalctl -u tapo-hub-face`. Relevant ports: HTTPS/control 443, camera uploads
21443, playback 8800, and UDP discovery 20002/20015. Keep these LAN-only.
Do not reset/unlink cameras or format storage as routine troubleshooting.

## Updates and development

Use **`tapo-hub update`** (or the installed `update` wrapper) after the source remote
is configured. It temporarily opens hub egress for the explicit update, then restores
the LAN-only policy even if the update fails. Private configuration,
models and recordings live outside the source installation. Back up before updates;
camera protocol changes require real-device acceptance as well as unit tests.
See [contributing](CONTRIBUTING.md), [privacy](docs/privacy.md),
[helper submission](docs/community-scripts.md) and [model attribution](NOTICE.md).
