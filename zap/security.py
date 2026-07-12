"""Key handling: per-user data key (DEK) wrapped by a key derived from the
master password (KEK). The server persists only salt + wrapped DEK; the
unwrapped DEK lives in an in-memory session vault with an idle timeout, so
nothing on disk can decrypt a vault without the user's password."""

import hashlib
import hmac
import secrets
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import abort, current_app, request, session

DEK_AAD = b"zap:dek-wrap:v1"
NONCE_LEN = 12
KEY_LEN = 32


def derive_kek(password: str, salt: bytes) -> bytes:
    cfg = current_app.config
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=cfg["SCRYPT_N"],
        r=cfg["SCRYPT_R"],
        p=cfg["SCRYPT_P"],
        maxmem=cfg["SCRYPT_MAXMEM"],
        dklen=KEY_LEN,
    )


def new_wrapped_dek(password: str) -> tuple[bytes, bytes, bytes]:
    """Returns (dek, kek_salt, dek_wrapped) for a fresh vault key."""
    dek = secrets.token_bytes(KEY_LEN)
    salt = secrets.token_bytes(16)
    kek = derive_kek(password, salt)
    return dek, salt, _seal(kek, dek, DEK_AAD)


def unwrap_dek(password: str, kek_salt: bytes, dek_wrapped: bytes) -> bytes:
    kek = derive_kek(password, kek_salt)
    return _open(kek, dek_wrapped, DEK_AAD)


def rewrap_dek(dek: bytes, new_password: str) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    kek = derive_kek(new_password, salt)
    return salt, _seal(kek, dek, DEK_AAD)


def credential_aad(user_id: int, credential_id: str) -> bytes:
    return f"zap:cred:v1:{user_id}:{credential_id}".encode()


def encrypt_secret(dek: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return _seal(dek, plaintext, aad)


def decrypt_secret(dek: bytes, blob: bytes, aad: bytes) -> bytes:
    return _open(dek, blob, aad)


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)


class SessionVault:
    """In-memory map of session token -> unlocked DEK. Deliberately not
    persisted: a restart relocks every vault. Single-process by design."""

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}

    def create(self, user_id: int, dek: bytes, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._entries[token] = [user_id, dek, time.monotonic() + ttl_seconds]
        return token

    def get(self, token: str, ttl_seconds: int):
        """Returns (user_id, dek) and slides the idle deadline, or None."""
        if not token:
            return None
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return None
            if time.monotonic() > entry[2]:
                del self._entries[token]
                return None
            entry[2] = time.monotonic() + ttl_seconds
            return entry[0], entry[1]

    def drop(self, token: str):
        with self._lock:
            self._entries.pop(token, None)

    def drop_user(self, user_id: int):
        with self._lock:
            stale = [t for t, e in self._entries.items() if e[0] == user_id]
            for t in stale:
                del self._entries[t]


session_vault = SessionVault()


def ensure_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="CSRF token missing or invalid")
