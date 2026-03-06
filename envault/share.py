"""
Share module: encode encrypted vault as a portable base64 string
that can be copy-pasted, sent via Slack/email, or stored in a secret manager.

Format:
  envault:<base64(encrypted_bytes)>

The recipient uses `envault import` with the same password to decrypt.
"""

import base64
from pathlib import Path
from typing import Optional

from .crypto import encrypt, decrypt

PREFIX = "envault:"


def export_string(env_path: Path, password: str) -> str:
    """
    Encrypt an env file and return a portable share string.
    The string starts with 'envault:' followed by base64-encoded ciphertext.
    """
    plaintext = env_path.read_bytes()
    ciphertext = encrypt(plaintext, password)
    b64 = base64.urlsafe_b64encode(ciphertext).decode("ascii")
    return f"{PREFIX}{b64}"


def import_string(share_string: str, password: str, output: Optional[Path] = None) -> tuple[str, Path]:
    """
    Decrypt a share string and write the env file.
    Returns (decrypted content, output path).
    """
    share_string = share_string.strip()
    if not share_string.startswith(PREFIX):
        raise ValueError("Invalid share string — must start with 'envault:'")

    b64 = share_string[len(PREFIX):]
    try:
        ciphertext = base64.urlsafe_b64decode(b64)
    except Exception:
        raise ValueError("Invalid base64 in share string")

    plaintext = decrypt(ciphertext, password)
    content = plaintext.decode("utf-8")

    out_path = output or Path(".env")
    out_path.write_bytes(plaintext)
    return content, out_path


def export_file(env_path: Path, password: str, output: Optional[Path] = None) -> Path:
    """
    Encrypt an env file and write a .envshare file (binary vault, portable).
    """
    plaintext = env_path.read_bytes()
    ciphertext = encrypt(plaintext, password)
    out = output or env_path.with_suffix(".envshare")
    out.write_bytes(ciphertext)
    return out


def string_size_kb(share_string: str) -> float:
    return len(share_string.encode("utf-8")) / 1024
