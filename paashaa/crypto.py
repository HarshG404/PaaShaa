"""Hashing + encryption primitives."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken

_N, _R, _P = 2 ** 14, 8, 1
_MAGIC = b"PSH1"


def hash_password(password: str, salt: bytes | None = None, n: int = _N, r: int = _R, p: int = _P) -> str:
    """scrypt hash, self-describing so parameters can be upgraded later."""
    salt = salt or os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * 1024 * 1024)
    return f"scrypt${n}${r}${p}${salt.hex()}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        cand = hash_password(password, bytes.fromhex(salt), int(n), int(r), int(p)).split("$")[-1]
        return hmac.compare_digest(cand, h)
    except (ValueError, TypeError):
        return False


class Vault:
    """Fernet (AES-128-CBC + HMAC) encryption of secrets at rest."""

    def __init__(self, key_path: str, use_keyring: bool = False):
        self._f = Fernet(self._load_key(key_path, use_keyring))

    @staticmethod
    def _load_key(path: str, use_keyring: bool) -> bytes:
        if use_keyring:
            try:
                import keyring
                k = keyring.get_password("PaaShaa", "vault-key")
                if not k:
                    k = Fernet.generate_key().decode()
                    keyring.set_password("PaaShaa", "vault-key", k)
                return k.encode()
            except Exception:
                pass  # fall back to key file
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(Fernet.generate_key())
        with open(path, "rb") as f:
            return f.read().strip()

    def encrypt(self, text: str) -> str:
        return self._f.encrypt(text.encode()).decode() if text else ""

    def decrypt(self, token: str) -> str:
        if not token:
            return ""
        try:
            return self._f.decrypt(token.encode()).decode()
        except InvalidToken as e:
            raise ValueError("Vault key does not match the stored data") from e


def _kdf(passphrase: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(hashlib.scrypt(passphrase.encode(), salt=salt, n=2 ** 15, r=8, p=1,
                                                   dklen=32, maxmem=128 * 1024 * 1024))


def seal(data: bytes, passphrase: str) -> bytes:
    """Passphrase-encrypt bytes (used for portable backups)."""
    salt = os.urandom(16)
    return _MAGIC + salt + Fernet(_kdf(passphrase, salt)).encrypt(data)


def unseal(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(_MAGIC):
        raise ValueError("Not a PaaShaa backup file")
    salt, token = blob[4:20], blob[20:]
    try:
        return Fernet(_kdf(passphrase, salt)).decrypt(token)
    except InvalidToken as e:
        raise ValueError("Wrong passphrase or corrupted backup") from e
