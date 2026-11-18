# Security policy

Tapo Hub is experimental software. It handles camera credentials, private video,
face images and biometric embeddings. It has not undergone an independent security
audit and should not be the sole recording system for security-critical use.

## Supported versions

Security fixes target the latest code on `main`. The initial `v0.1.0` prerelease
is for evaluation; older snapshots do not receive separate backported fixes.
Update to the latest reviewed code when a fix is published. There is no guaranteed
response time or long-term support commitment.

## Report a vulnerability privately

Use GitHub's [private vulnerability reporting](https://github.com/mnrmurilo/Tapo-hub/security/advisories/new).
If that option is unavailable, open an issue asking only for a private security
contact, without describing the vulnerability or including sensitive data.

Include the affected commit/version, a description of the impact, prerequisites,
and minimal reproduction steps using synthetic data. Relevant areas include
unauthorized playback or control, authentication bypass, unsafe media processing,
path traversal, installer/update integrity and disclosure of recordings or face data.

Do not send passwords, tokens, private keys, real camera inventories, recordings,
face photos or embeddings. Redact logs before sharing. Test only systems you own
or have permission to assess; avoid disrupting recording or modifying other users'
data. Coordinate public disclosure after the maintainer has assessed the report
and a fix or mitigation is available.

## Deployment precautions and limitations

- Keep the hub on a trusted LAN in a dedicated unprivileged LXC. Do not forward
  discovery, control, upload or playback ports to the internet.
- Restrict access to configuration, state, recordings and backups. Face embeddings
  are sensitive data. This project does not provide application-level encryption
  at rest; configure host/storage encryption separately if needed.
- Use dedicated recording storage. Keep unrelated applications and data outside
  the hub's mounts. Back up before installing or updating.
- Setup and explicit updates download packages and models. Review scripts and
  model terms before running them. Hash-locked Python dependencies and model
  hashes do not constitute independent verification of upstream software.
- Runtime LAN-only egress restrictions apply to the hub, not to the Tapo app or
  cameras. Local inference does not establish that those devices are cloud-free.
- Interrupted battery-camera uploads can leave missing or incomplete footage.
  Recognition can miss or misidentify people; do not use it for access control.

See [privacy](docs/privacy.md) and [known limitations](README.md) for more context.
