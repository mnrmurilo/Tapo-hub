# Source release privacy

The repository is an explicit source-only export. It contains generic examples,
original code, synthetic tests, model manifests and documentation. It does not
contain a home network inventory, real camera MACs, a personal home-lab title,
live configuration, credentials, face images/templates, recordings or captures.

All camera selection and storage configuration is supplied at installation time.
There is no preconfigured camera, host mount, storage pool or account.

Local AI runs on the LXC. Model/package downloads require internet during setup,
but do not upload face data. Runtime hub egress is limited to the configured LAN.
The Tapo phone app and the cameras have independent network behavior: this project
does not claim to disable their cloud traffic. Native cloud push is unsupported.

Use `git ls-files` and `python3 scripts/check-release.py` before releasing. Never
create an application source archive by recursively copying a live installation.
Use `git archive` on the reviewed source commit; runtime data and weights remain
outside Git and outside release artifacts.
