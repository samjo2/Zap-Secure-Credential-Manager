"""Tamper-evident audit log: per-user HMAC hash chain. Each entry's hash
covers the previous entry's hash, so editing or deleting any row breaks
verification of everything after it. Replaces the old on-chain keccak of
service:username:password, which published an offline-crackable digest."""

import hashlib
import hmac
from datetime import datetime, timezone

from flask import current_app

GENESIS = "0" * 64


def _audit_key() -> bytes:
    secret = current_app.secret_key
    if isinstance(secret, str):
        secret = secret.encode()
    return hmac.new(secret, b"zap:audit-key:v1", hashlib.sha256).digest()


def _entry_hash(key: bytes, user_id: int, at: str, action: str, detail: str, prev: str) -> str:
    payload = "|".join([str(user_id), at, action, detail, prev]).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def record(db, user_id: int, action: str, detail: str = ""):
    row = db.execute(
        "SELECT entry_hash FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    prev = row["entry_hash"] if row else GENESIS
    at = datetime.now(timezone.utc).isoformat()
    entry = _entry_hash(_audit_key(), user_id, at, action, detail, prev)
    db.execute(
        "INSERT INTO audit_log (user_id, at, action, detail, prev_hash, entry_hash)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, at, action, detail, prev, entry),
    )


def verify_chain(db, user_id: int) -> bool:
    key = _audit_key()
    prev = GENESIS
    rows = db.execute(
        "SELECT at, action, detail, prev_hash, entry_hash FROM audit_log"
        " WHERE user_id = ? ORDER BY id",
        (user_id,),
    ).fetchall()
    for row in rows:
        if row["prev_hash"] != prev:
            return False
        expected = _entry_hash(key, user_id, row["at"], row["action"], row["detail"], prev)
        if not hmac.compare_digest(expected, row["entry_hash"]):
            return False
        prev = row["entry_hash"]
    return True


def entries_for(db, user_id: int):
    return db.execute(
        "SELECT at, action, detail FROM audit_log WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()
