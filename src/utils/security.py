import os
from cryptography.fernet import Fernet

def ensure_permissions(path):
    os.chmod(path, 0o600)

def encrypt_secrets(data, key_path):
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, 'wb') as kf:
            kf.write(key)
    else:
        with open(key_path, 'rb') as kf:
            key = kf.read()
    f = Fernet(key)
    return f.encrypt(data.encode())
