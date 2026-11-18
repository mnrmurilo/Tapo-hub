# Contributing

Use Python 3.13 and the hash-locked dependencies. From the repository root:

```sh
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python --require-hashes -r requirements.lock
PYTHONPATH=app .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
python3 scripts/check-release.py
bash -n ct/tapo-hub.sh install/tapo-hub-install.sh scripts/install-runtime.sh
```

Use synthetic fixtures. Never commit configuration, camera MAC/IP inventories,
account hashes/tokens, profiles, footage, packet captures, vendor binaries or model
weights. Keep external protocol-research materials outside this repository.

Changes to camera protocols need sanitized regression fixtures and real-device
validation before claiming support. A private replay validates only the exercised
path; it does not establish iPhone compatibility or long-term upload reliability.

The application and community helper are reviewed separately. New community-scripts
helpers go to DevScripts first; follow its current AGENTS.md and contribution rules.
The helper defaults to mnrmurilo/Tapo-hub and permits a compatible fork override.
Publish a tagged release and complete the clean-host one-command test before
requesting upstream inclusion.
