from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from src.app.backend.util import config
from icecream import ic
import hashlib
import os


def encrypt_private_key(private_key_path: str, pin: str) -> str:
    try:
        with open(private_key_path, 'rb') as f:
            private_key_data = f.read()
        key = hashlib.sha256(pin.encode()).digest()
        iv = os.urandom(config.BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padding_length = config.BLOCK_SIZE - (len(private_key_data) % config.BLOCK_SIZE)
        private_key_data += bytes([padding_length]) * padding_length
        encrypted_private_key = iv + encryptor.update(private_key_data) + encryptor.finalize()
        encrypted_key_path = private_key_path.replace("SoCS-private-key.pem", "SoCS-encrypted-private-key.pem")
        os.remove(private_key_path)
        with open(encrypted_key_path, 'wb') as f:
            f.write(encrypted_private_key)
        return encrypted_key_path
    except Exception as ex:
        ic(f"{ex}")
        return ""


def decrypt_private_key(encrypted_key_path: str, pin: str) -> str:
    try:
        with open(encrypted_key_path, 'rb') as f:
            encrypted_private_key_data = f.read()
        key: bytes = hashlib.sha256(pin.encode()).digest()
        iv: bytes = encrypted_private_key_data[:config.BLOCK_SIZE]
        encrypted_data: bytes = encrypted_private_key_data[config.BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decrypted_private_key_data: bytes = cipher.decryptor().update(encrypted_data) + cipher.decryptor().finalize()
        padding_length: int = decrypted_private_key_data[-1]
        if padding_length < 1 or padding_length > config.BLOCK_SIZE:
            raise ValueError("Invalid padding length!")
        decrypted_private_key_data: bytes = decrypted_private_key_data[:-padding_length]
        decrypted_key_path = encrypted_key_path.replace("SoCS-encrypted-private-key.pem", "SoCS-private-key.pem")
        with open(decrypted_key_path, 'wb') as f:
            f.write(decrypted_private_key_data)
        os.remove(encrypted_key_path)
        ic(f"{decrypted_key_path}")
        return decrypted_key_path
    except Exception as ex:
        ic(f"{ex}")
        return ""