"""
Crypto Utilities Module
Author: Bishesh Dulal
Date: March 2025

Description:
This module provides AES encryption and decryption utilities for
the JWKS Server. It uses:
- AES-128/192/256 CBC mode with PKCS7 padding
- Environment-based secure key loading
- Automatic IV generation and Base64 encoding
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# --- AES Configuration ---
AES_KEY = os.getenv("NOT_MY_KEY", "").encode()
backend = default_backend()

def validate_key(key: bytes):
    """Validate that the AES key is bytes and has valid length (16, 24, or 32 bytes)."""
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")
    if len(key) not in {16, 24, 32}:
        raise ValueError(
            f"Invalid AES key length: {len(key)} bytes. "
            "Key must be 16, 24, or 32 bytes. "
            "Set NOT_MY_KEY environment variable correctly."
        )

# --- Validate Loaded Key ---
try:
    validate_key(AES_KEY)
except ValueError as e:
    print("CRITICAL ERROR:", str(e))
    print(f"Current key: '{AES_KEY.decode()}' (length: {len(AES_KEY)})")
    exit(1)

# --- Encryption and Decryption Functions ---
def encrypt(plaintext: str) -> tuple[str, str]:
    """
    Encrypt plaintext using AES-CBC with PKCS7 padding.
    
    Args:
        plaintext (str): The plain text to encrypt.

    Returns:
        tuple[str, str]: Base64-encoded (ciphertext, iv)
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

def decrypt(ciphertext_b64: str, iv_b64: str) -> str:
    """
    Decrypt Base64-encoded ciphertext using AES-CBC with PKCS7 unpadding.

    Args:
        ciphertext_b64 (str): Base64-encoded ciphertext.
        iv_b64 (str): Base64-encoded initialization vector.

    Returns:
        str: Decrypted plaintext.
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode()
