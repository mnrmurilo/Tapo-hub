# Community helper candidate

The repository provides `ct/tapo-hub.sh`, `install/tapo-hub-install.sh` and
`json/tapo-hub.json`. The helper loads the community-scripts shared engine and
uses its release fetch, Python/uv, OS setup and update helpers. It creates a
Debian13 unprivileged LXC, asks for a new dedicated recording volume, and runs
the application's guided network/camera/model setup.

New scripts must be submitted to https://github.com/community-scripts/DevScripts
for testing before promotion to ProxmoxVE. This repository is not an accepted
community-scripts listing. Application source and metadata point to
https://github.com/mnrmurilo/Tapo-hub; the release-based installer still requires
a first tagged release.

Pre-submit checklist:

- Publish the reviewed application source and tag its first release.
- Verify website/repository/documentation metadata resolves publicly.
- Run the real one-command helper from a clean Proxmox host against that release.
- Test the interactive storage/camera/model questions and unattended `var_*` inputs.
- Keep source configuration, models and recordings outside release/update files.
- Include a testing report, tested device/hardware/firmware matrix and known limitations.
- Mention that only amd64 has been tested; do not claim ARM or Incus acceptance.
- Request DevScripts review and follow maintainers' feedback and promotion process.

The standalone helper loads its install script from mnrmurilo/Tapo-hub/main.
When proposing the helper to DevScripts, change its default helper source to the
upstream location; keep the application's release source separate. No access tokens
are embedded in the helper.
