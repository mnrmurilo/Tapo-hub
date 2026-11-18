# Local validation — 2026-11-18

- The clean unprivileged Debian 13 amd64 LXC installation checks passed, including FFmpeg publication and localhost protocol tests.
- The patched source suite runs 240 tests in the clean Debian 13 test LXC: all pass, including real FFmpeg interrupted-stream finalization. The host skips the two FFmpeg-dependent tests.
- Astral uv creates the environment and installs hash-locked dependencies in the installer, updater and CI.
- A source-only archive installed into the fresh guest using hash-locked dependencies.
- An empty dedicated 4 GiB test recording volume initialized successfully; root-disk and unrelated-data refusal have regression coverage.
- Synthetic camera selection and a user-supplied compatible ArcFace file were exercised. No real camera inventory, face profiles or credentials were imported.
- Live doctor checks passed: local UDP discovery, matching discovery/control identity, encrypted HTTPS authentication, healthy dedicated storage, and ready local face inference.
- Re-running configuration preserved the existing model and passed automatic readiness checks.
- Mocked helper-contract tests cover new-volume allocation, preservation of an existing mount point and invalid-size rejection.
- Source artifact scanning, a separate personal-configuration residue scan and Bash syntax checks passed.
- The temporary guest was stopped after verification; the existing hub was not reconfigured.

The public GitHub release download and real upstream one-command host workflow are
not tested yet: the application remote is configured, but the first tagged release
is still pending (v0.1.0 is an experimental prerelease). The local
install test exercised the guest installation path, not an accepted DevScripts listing.
Physical camera pairing was not repeated in the clean guest; its discovery subnet
was isolated from the operational camera LAN. Model download/terms acknowledgement
is available but the live smoke test used the compatible-file model path.

Audit regression checks also verify private model-bundle recovery, complete bounded
face-gallery synchronization, full unknown-gallery handling, bounded idle HTTP
clients, concurrent authenticated dispatch, index-cache invalidation and recorder
configuration. Real test-LXC checks confirmed temporary network access restores
the firewall without restarting the hub, and a changed synthetic LAN subnet is
applied while encrypted control and local AI remain healthy.
