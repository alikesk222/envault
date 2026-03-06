"""
AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation.
All crypto primitives from the `cryptography` library (no custom crypto).
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Key derivation parameters
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-SHA256
SALT_SIZE = 32   # 256-bit salt
NONCE_SIZE = 12  # 96-bit nonce (GCM standard)
KEY_SIZE = 32    # AES-256
TAG = b"ENVAULT1"  # File format magic

# Wire format:
#   [8 bytes magic] [4 bytes iterations] [32 bytes salt] [12 bytes nonce] [ciphertext+tag]


def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    iterations_bytes = struct.pack(">I", PBKDF2_ITERATIONS)
    return TAG + iterations_bytes + salt + nonce + ciphertext


def decrypt(data: bytes, password: str) -> bytes:
    if not data.startswith(TAG):
        raise ValueError("Not a valid envault file (bad magic bytes)")
    offset = len(TAG)
    iterations = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    salt = data[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]
    key = _derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password or corrupted file")
