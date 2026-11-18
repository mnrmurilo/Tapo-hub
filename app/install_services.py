"""Install application-owned units without starting an unconfigured hub."""
import os
from pathlib import Path
import shutil
import subprocess

if __name__ == '__main__':
    if os.geteuid() != 0 or subprocess.run(['systemd-detect-virt', '--container'], stdout=subprocess.DEVNULL).returncode:
        raise SystemExit('Run only as root inside a dedicated LXC')
    source = Path(__file__).resolve().parent.parent
    for path in ('/etc/tapo-hub', '/var/lib/tapo-hub'):
        Path(path).mkdir(mode=0o700, exist_ok=True)
    for unit in (source/'systemd').glob('*.service'):
        destination = Path('/etc/systemd/system')/unit.name
        shutil.copyfile(unit, destination)
        destination.chmod(0o644)
    command = Path('/usr/local/bin/tapo-hub')
    command.write_text('#!/usr/bin/env bash\nexec /opt/tapo-hub/.venv/bin/python /opt/tapo-hub/app/manage.py "$@"\n')
    command.chmod(0o755)
    updater = Path('/usr/local/bin/update')
    updater.write_text('#!/usr/bin/env bash\nexec /usr/local/bin/tapo-hub update\n')
    updater.chmod(0o755)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
