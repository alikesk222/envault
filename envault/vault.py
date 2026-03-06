"""
Vault operations: lock (.env -> .env.vault) and unlock (.env.vault -> .env).
Also handles view (decrypt to stdout without writing) and diff.
"""

import os
import re
from pathlib import Path
from typing import Optional

from .crypto import encrypt, decrypt

DEFAULT_VAULT_EXT = ".vault"


def _read_file(path: Path) -> bytes:
    return path.read_bytes()


def _write_file(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def lock(env_path: Path, password: str, output: Optional[Path] = None, overwrite: bool = False) -> Path:
    """
    Encrypt an .env file and write it as .env.vault.
    Returns the vault file path.
    """
    if not env_path.exists():
        raise FileNotFoundError(f"File not found: {env_path}")

    vault_path = output or env_path.with_suffix(env_path.suffix + DEFAULT_VAULT_EXT)

    if vault_path.exists() and not overwrite:
        raise FileExistsError(
            f"Vault file already exists: {vault_path}. Use --overwrite to replace it."
        )

    plaintext = _read_file(env_path)
    ciphertext = encrypt(plaintext, password)
    _write_file(vault_path, ciphertext)
    return vault_path


def unlock(
    vault_path: Path,
    password: str,
    output: Optional[Path] = None,
    overwrite: bool = False,
) -> Path:
    """
    Decrypt a .env.vault file and write the .env file.
    Returns the output file path.
    """
    if not vault_path.exists():
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    # Derive output path: strip the .vault suffix
    if output is None:
        name = vault_path.name
        if name.endswith(DEFAULT_VAULT_EXT):
            out_name = name[: -len(DEFAULT_VAULT_EXT)]
            output = vault_path.parent / out_name
        else:
            output = vault_path.with_suffix(".env")

    if output.exists() and not overwrite:
        raise FileExistsError(
            f"Output file already exists: {output}. Use --overwrite to replace it."
        )

    ciphertext = _read_file(vault_path)
    plaintext = decrypt(ciphertext, password)
    _write_file(output, plaintext)
    return output


def view(vault_path: Path, password: str) -> str:
    """Decrypt vault and return content as string (never writes to disk)."""
    if not vault_path.exists():
        raise FileNotFoundError(f"Vault file not found: {vault_path}")
    ciphertext = _read_file(vault_path)
    plaintext = decrypt(ciphertext, password)
    return plaintext.decode("utf-8")


def parse_env(content: str) -> dict[str, str]:
    """Parse .env file content into a dict, skipping comments and blanks."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip surrounding quotes
            if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
                value = value[1:-1]
            result[key] = value
    return result


def mask_value(value: str) -> str:
    """Mask a secret value for display."""
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
