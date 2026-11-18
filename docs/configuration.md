# Configuration and storage choices

Run `tapo-hub configure` in the dedicated LXC. The helper creates a new Proxmox
recording volume on the pool and at the size chosen by the user. To use an existing
**empty dedicated volume**, attach it as an LXC mount point at
`/var/lib/tapo-hub/recordings` before configuration. Setup never formats a device,
changes a host photo directory, or adopts a nonempty unrelated volume.

The following addresses and locally administered MAC are fictional examples:

```json
{
  "hub_ip": "10.23.0.2",
  "lan_cidr": "10.23.0.0/24",
  "timezone": "Etc/UTC",
  "recording_path": "/var/lib/tapo-hub/recordings",
  "cameras": [
    {
      "model": "C400",
      "hardware_version": "2.0",
      "mac": "02:00:00:00:00:01",
      "ip": "10.23.0.10",
      "continuous": false
    }
  ]
}
```

Save your own configuration outside the repository with mode0600, then:

```sh
tapo-hub configure --config-file /root/private-setup.json --models later
```

For the tested download use `--models download --accept-model-terms` only after
reviewing the model terms. For an authorized compatible model use
`--models file --model-path /root/recognition.onnx`. The latter still downloads
the checksum-pinned YuNet detector. See the README for input/embedding requirements.

Configuration contains private camera identifiers but no installer-requested Tapo
password. Account association in the Tapo app creates private runtime authentication
material; exclude `/etc/tapo-hub` and `/var/lib/tapo-hub` from source releases.
The selected cameras are discovery candidates; authenticated pairing remains a
separate Tapo step. Changing the allowlist does not delete saved video or replace
an explicit unpair operation for an already enrolled camera.

`continuous: true` is supported only for TC70 hardware5.x, with one recorder per
hub. TC70 hub storage cannot be enabled while this option is false; event-only TC70
reception is not implemented. Reconfiguring with false stops and disables the old
recorder instance. The true setting enables a recorder
instance after that camera is paired and selects hub storage. Camera-side recording
settings are not silently rewritten. Battery-camera live view is not used as a
permanent substitute for motion/doorbell events.

Back up configuration, private association state, models, recordings and the face
database consistently before migration. Preserve the LXC MAC when restoring the
same hub: its device identity is derived from that MAC. A brand-new LXC has a new
identity and requires new pairing. Never copy one hub identity into two running LXCs.
