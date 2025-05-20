import os
import yaml
from cryptography.fernet import Fernet
from pathlib import Path

def load_config(config_path=None):
    config_file = config_path or os.getenv('IONOS_WP_MANAGER_CONFIG') or os.path.expanduser('~/.config/ionos_wp_manager/config.yml')
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config-Datei nicht gefunden: {config_file}. Bitte führe das Setup-Skript aus oder lege die Datei an.")
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def save_credentials(creds: dict, encrypt=True):
    cred_dir = os.path.expanduser('~/.config/ionos_wp_manager')
    os.makedirs(cred_dir, exist_ok=True)
    cred_file = os.path.join(cred_dir, 'credentials')
    if encrypt:
        key_file = os.path.join(cred_dir, 'key')
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, 'wb') as kf:
                kf.write(key)
        else:
            with open(key_file, 'rb') as kf:
                key = kf.read()
        f = Fernet(key)
        data = f.encrypt(yaml.dump(creds).encode())
        with open(cred_file, 'wb') as cf:
            cf.write(data)
    else:
        with open(cred_file, 'w') as cf:
            yaml.dump(creds, cf)
    os.chmod(cred_file, 0o600)

def validate_prefix(prefix: str):
    import re
    # Erlaube Bindestriche, aber nicht am Anfang/Ende und nicht mehrfach hintereinander
    if not re.match(r'^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$', prefix):
        raise ValueError('Prefix darf Buchstaben, Zahlen und Bindestriche enthalten, aber nicht mit Bindestrich beginnen/enden oder doppelte Bindestriche enthalten.')
    return prefix

def load_credentials():
    import os
    import yaml
    from cryptography.fernet import Fernet
    cred_dir = os.path.expanduser('~/.config/ionos_wp_manager')
    cred_file = os.path.join(cred_dir, 'credentials')
    key_file = os.path.join(cred_dir, 'key')
    if not os.path.exists(cred_file) or not os.path.exists(key_file):
        raise FileNotFoundError("Credentials oder Key fehlen. Bitte führe 'init' aus.")
    with open(key_file, 'rb') as kf:
        key = kf.read()
    f = Fernet(key)
    with open(cred_file, 'rb') as cf:
        data = f.decrypt(cf.read())
        return yaml.safe_load(data)
