"""
@file security.py
@brief Module for encrypting, decrypting RSA private keys, signing PDF documents, and verifying PDF signatures.
"""
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from PyPDF2 import PdfReader, PdfWriter
from src.app.backend.util import config
from datetime import datetime
from icecream import ic
import hashlib
import os


def encrypt_private_key(private_key_path: str, pin: str) -> str:
    """
    @brief Encrypts a private RSA key using AES encryption with a PIN-derived key.

    @param private_key_path Path to the private key file to be encrypted.
    @param pin User-provided PIN used to derive the AES encryption key.
    @return str Path to the newly created encrypted private key file, or an empty string if encryption fails.
    """
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
    """
    @brief Decrypts an AES-encrypted private RSA key using a PIN-derived key.

    @param encrypted_key_path Path to the encrypted private key file.
    @param pin User-provided PIN used to derive the AES decryption key.
    @return str Path to the decrypted private key file, or an empty string if decryption fails.
    """
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


def sign_pdf(pdf_path: str, private_key_path: str, name: str) -> str:
    """
    @brief Signs a PDF file by creating a digital signature with the provided private RSA key.

    @param pdf_path Path to the PDF file to be signed.
    @param private_key_path Path to the private key used for signing.
    @param name Name of the signer to embed into the PDF metadata.
    @return str Path to the signed PDF file.
    """
    pdf_reader = PdfReader(pdf_path)
    pdf_writer = PdfWriter()
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)
    pdf_content = b"".join([page.extract_text().encode() for page in pdf_reader.pages])
    with open(private_key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)
    signature = private_key.sign(
        pdf_content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    pdf_writer.add_metadata({
        "/Signature": signature.hex(),
        "/Name": name,
        "/Date": datetime.now().isoformat()
    })
    signed_pdf_path = pdf_path.replace(".pdf", "-signed.pdf")
    with open(signed_pdf_path, "wb") as signed_pdf:
        pdf_writer.write(signed_pdf)
    return signed_pdf_path


def verify_pdf(pdf_path: str, public_key_path: str) -> [bool, str, str, int, int]:
    """
    @brief Verifies the digital signature of a signed PDF file using the provided public RSA key.

    @param pdf_path Path to the signed PDF file to be verified.
    @param public_key_path Path to the public key used for verification.
    @return list [bool, str, str, int, int] Verification result (True/False), signer name, signature date, signature length in bytes, and public key size.
    """
    pdf_reader = PdfReader(pdf_path)
    pdf_content = b"".join([page.extract_text().encode() for page in pdf_reader.pages])
    with open(public_key_path, "rb") as key_file:
        public_key = load_pem_public_key(key_file.read())
    signature_hex = pdf_reader.metadata.get("/Signature")
    if signature_hex is None:
        return False, None, None, None, None
    name = pdf_reader.metadata.get("/Name")
    date = pdf_reader.metadata.get("/Date")
    signature = bytes.fromhex(signature_hex)
    try:
        public_key.verify(
            signature,
            pdf_content,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        ic(f"✅")
        return True, name, date, len(signature), public_key.key_size
    except Exception as ex:
        ic(f"❌ : {ex}")
        return False, None, None, None, None
