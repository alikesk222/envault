import pytest

from envault.crypto import encrypt, decrypt


def test_roundtrip():
    plaintext = b"SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n"
    blob = encrypt(plaintext, "correct horse battery staple")
    assert decrypt(blob, "correct horse battery staple") == plaintext


def test_wrong_password_fails():
    blob = encrypt(b"top secret", "right-password")
    with pytest.raises(ValueError):
        decrypt(blob, "wrong-password")


def test_corrupted_file_rejected():
    with pytest.raises(ValueError):
        decrypt(b"not-an-envault-file", "any-password")


def test_ciphertext_differs_from_plaintext():
    plaintext = b"SECRET=value"
    blob = encrypt(plaintext, "password")
    assert plaintext not in blob


def test_same_plaintext_different_ciphertext():
    plaintext = b"SECRET=value"
    blob1 = encrypt(plaintext, "password")
    blob2 = encrypt(plaintext, "password")
    assert blob1 != blob2  # random salt/nonce each time
