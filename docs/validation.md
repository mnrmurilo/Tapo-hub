# Local validation — 2026-11-18

- The clean unprivileged Debian 13 amd64 LXC installation checks passed, including FFmpeg publication and localhost protocol tests.
- The current source suite runs 226 tests on the host: all applicable tests pass, with one FFmpeg-dependent test skipped there. The earlier clean-guest run also covered that test successfully.
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
is still pending. The local
install test exercised the guest installation path, not an accepted DevScripts listing.
Physical camera pairing was not repeated in the clean guest; its discovery subnet
was isolated from the operational camera LAN. Model download/terms acknowledgement
is available but the live smoke test used the compatible-file model path.
