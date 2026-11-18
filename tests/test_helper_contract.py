"""Exercise the host helper with mocked engine/Proxmox commands, never real pct."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class HelperContractTests(unittest.TestCase):
    def run_helper(self, *, existing=False, size='12'):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root/'core').mkdir()
            (root/'core'/'build.func').write_text('''
header_info() { :; }
variables() { CTID=99999; CONTAINER_STORAGE=example-storage; }
color() { INFO=; YW=; CL=; }
catch_errors() { set -e; }
validate_storage_space() { :; }
prompt_input_required() { case "$4" in var_repository) echo example/Tapo-hub;; var_recording_storage) echo example-storage;; var_recording_gb) echo "$TEST_SIZE";; esac; }
start() { :; }
build_container() { :; }
description() { :; }
msg_info() { :; }
msg_ok() { :; }
msg_error() { echo "$*" >&2; }
''')
            for name, script in {
                'pct': '''#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$TEST_CALLS"
if [[ "$1" == config && "$TEST_EXISTING" == yes ]]; then echo 'mp0: do-not-replace'; fi
''',
                'pvesm': '#!/usr/bin/env bash\necho "example-storage dir active 1000000 1000 999000"\n'
            }.items():
                path = root/name
                path.write_text(script)
                path.chmod(0o755)
            calls = root/'calls'
            env = {**os.environ, 'COMMUNITY_SCRIPTS_CORE_DIR': str(root), 'PATH': f'{root}:/usr/bin:/bin',
                   'TEST_CALLS': str(calls), 'TEST_EXISTING': 'yes' if existing else 'no', 'TEST_SIZE': size}
            result = subprocess.run(['bash', str(Path(__file__).resolve().parents[1]/'ct'/'tapo-hub.sh')],
                                    env=env, capture_output=True, text=True, timeout=10)
            return result, calls.read_text() if calls.exists() else ''

    def test_default_source_repository(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("ct/tapo-hub.sh", "install/tapo-hub-install.sh"):
            self.assertIn('var_repository="${var_repository:-mnrmurilo/Tapo-hub}"', (root/name).read_text())
        self.assertIn("https://raw.githubusercontent.com/mnrmurilo/Tapo-hub/main", (root/"ct/tapo-hub.sh").read_text())

    def test_new_recording_volume_and_guided_setup(self):
        result, calls = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('set 99999 --mp0 example-storage:12,mp=/var/lib/tapo-hub/recordings,backup=1', calls)
        self.assertIn('/usr/local/bin/tapo-hub configure', calls)

    def test_existing_mount_is_preserved(self):
        result, calls = self.run_helper(existing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('set 99999', calls)

    def test_invalid_size_allocates_nothing(self):
        result, calls = self.run_helper(size='0')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('set 99999', calls)
