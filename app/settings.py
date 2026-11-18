"""Installation settings. Runtime files never belong in the source repository."""
import ipaddress
import json
import os
from pathlib import Path

CONFIG_PATH = Path(os.environ.get('TAPO_CONFIG', '/etc/tapo-hub/config.json'))
CONFIG = json.loads(CONFIG_PATH.read_text()) if CONFIG_PATH.exists() else {}
LAN = ipaddress.IPv4Network(CONFIG.get('lan_cidr', '10.23.0.0/22'))
STORE = Path(CONFIG.get('recording_path', '/var/lib/tapo-hub/recordings'))
MODELS = Path('/var/lib/tapo-hub/models')


def validate(config):
    network = ipaddress.IPv4Network(config['lan_cidr'], strict=False)
    address = ipaddress.IPv4Address(config['hub_ip'])
    if (not network.is_private or network.is_loopback or network.is_link_local or address not in network
            or address in (network.network_address, network.broadcast_address)):
        raise ValueError('Choose a private LAN subnet containing this hub address')
    if config['recording_path'] != '/var/lib/tapo-hub/recordings':
        raise ValueError('Mount the selected dedicated recording volume at /var/lib/tapo-hub/recordings')
    config['lan_cidr'] = str(network)
    return config
