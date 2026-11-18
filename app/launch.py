"""Start the configured hub; an unconfigured install never advertises a device."""
import logging
from types import SimpleNamespace

from settings import CONFIG, validate
from hub_lab import serve

if __name__ == '__main__':
    validate(CONFIG)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    serve(SimpleNamespace(ip=CONFIG['hub_ip'], model='H500',
        cert='/etc/tapo-hub/cert.pem', key='/etc/tapo-hub/key.pem',
        state_file='/var/lib/tapo-hub/state.json', cloud_ca='/etc/ssl/certs/ca-certificates.crt',
        enable_cloud_registration=False, local_only_setup=True))
