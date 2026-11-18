# Initial audit fixes

The initial ponytail audit found ten reliability, security and scaling issues.
These changes address the concrete failure paths without adding model weights,
private configuration, TV features or additional dependencies.

| Finding | Change |
|---|---|
| Update checks could stop recording | Temporary download access leaves the firewall service and its dependent hub running. Failed release deployment restores the previous application, environment, configuration and version marker before restarting services. |
| TC70 option was not enforced | Configuration preserves the continuous opt-in, permits one recorder, reconciles enabled instances, and refuses TC70 hub-storage activation without a configured recorder. |
| Interrupted continuous video lost its tail | Camera errors drain the muxer and publish segments that pass codec validation before reconnecting. Missing or invalid footage is not advertised as recovered. |
| Failed model setup replaced working weights | All downloads are staged and validated first. Bundle-switch failure restores the previous bundle; failed reconfiguration restores prior configuration and models. |
| LAN changes left old firewall rules | Setup validates and applies the new rules explicitly; failure recovery restores the previous rules. |
| Idle playback clients used unlimited threads | HTTP and HTTPS listeners share connection limits and accept-time socket timeouts. |
| Face synchronization omitted later profiles | Full gallery requests return the complete bounded gallery. Explicit small preview limits do not advance the synchronization cursor past unseen profiles. |
| Unknown faces exhausted familiar recognition | Familiar and unknown profiles each have a 300-profile limit. A full unknown gallery skips new unknown additions and continues familiar matching. |
| Slow commands blocked other clients | Authentication reserves replay sequences under its lock, then releases it before executing commands. |
| Index files were repeatedly reread | Playback caches decoded metadata, checks file identity/change signatures and discards entries when recordings disappear. |

Regression checks use synthetic data. The clean test LXC passed all 240 tests,
including real FFmpeg validation of the received tail after a simulated camera
connection loss. Real service checks also exercised network-failure recovery and
changed-subnet reconfiguration.

The legacy live installation receives equivalent runtime changes while retaining
its existing service account, paths, camera associations and private features.
The new installer/updater management code is tested in the isolated installation
LXC; it is not used to replace an older deployment's layout automatically.

These fixes do not guarantee recovery of bytes a camera never transmitted. Native
face-event push, Wi-Fi fallback, complete H500 parity and upstream helper acceptance
remain outside this patch. Existing release tags are not rewritten.
