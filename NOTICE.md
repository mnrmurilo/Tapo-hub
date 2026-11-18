# Attribution and model terms

The original implementation references python-kasa discovery/AES transport,
cB-Sigma/tplink-sim (Apache-2.0), and published native-protocol research by Imre Rad.
No vendor firmware, extracted APK, decompiled source, device certificate or private
protocol capture is included in this repository.

The Proxmox helper layout follows community-scripts (MIT); its shared engine is
loaded from that project. Contributions must follow its current DevScripts process.

Face inference uses OpenCV, NumPy, YuNet and ArcFace. Each dependency retains its
own license. InsightFace code licensing does not grant permission to use its
pretrained weights: upstream specifies non-commercial research use for those
weights. They are not bundled. The setup offers an explicit terms-reviewed
download or a user-supplied compatible, licensed model. YuNet's license is saved
beside its downloaded weights. See https://github.com/deepinsight/insightface/tree/master/python-package#license .

Tapo and TP-Link are trademarks of their owners. This is an independent,
experimental implementation, not official H500 firmware or an affiliated product.
