from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from icecream import ic
from src.app.backend.util import config
from datetime import datetime
import os


def generate_rsa_keys() -> tuple[str, str]:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_LENGTH,
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_key


def generate_and_save_keys(device_path: str) -> tuple[str, str]:
    private_key, public_key = generate_rsa_keys()

    current_time: datetime = datetime.now()
    formatted_time: str = current_time.strftime("%Y%m%d-%H%M%S")
    keys_dir: str = os.path.join(device_path, f"pades-keys-{formatted_time}")
    try:
        os.makedirs(keys_dir, exist_ok=True)
        private_key_path = os.path.join(keys_dir, "SoCS-private-key.pem")
        public_key_path = os.path.join(keys_dir, "SoCS-public-key.pem")

        with open(private_key_path, "w") as private_key_file:
            private_key_file.write(private_key)
        with open(public_key_path, "w") as public_key_file:
            public_key_file.write(public_key)

        remove_unwanted_files(device_path)
    except Exception as ex:
        raise ex

    return private_key_path, public_key_path


def count_keys(directory: str) -> tuple[int, int, list[str], list[str]]:
    private_key_count: int = 0
    public_key_count: int = 0
    private_key_paths: list[str] = []
    public_key_paths: list[str] = []
    remove_unwanted_files(directory)

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file in config.PRIVATE_KEY_FILES:
                private_key_count += 1
                private_key_paths.append(file_path)
            elif file in config.PUBLIC_KEY_FILES:
                public_key_count += 1
                public_key_paths.append(file_path)

    return private_key_count, public_key_count, private_key_paths, public_key_paths


def remove_unwanted_files(directory: str) -> None:
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file in config.UNWANTED_FILES or file.startswith("._pades-keys-"):
                try:
                    os.remove(file_path)
                    ic(f"{file_path}")
                except Exception as ex:
                    raise ex
