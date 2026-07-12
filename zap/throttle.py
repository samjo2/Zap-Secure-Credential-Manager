"""Login rate limiting. Failures are counted per (username, IP) pair so an
attacker hammering a victim's username only locks their own IP, not the
victim; a wider per-IP cap stops single-source spraying across usernames."""

from datetime import datetime, timedelta, timezone

from flask import current_app


def _now():
    return datetime.now(timezone.utc)


def _keys(username: str, ip: str) -> tuple[str, str]:
    return f"u:{username.lower()}|ip:{ip}", f"ip:{ip}"


def is_locked(db, username: str, ip: str) -> bool:
    now = _now().isoformat()
    for key in _keys(username, ip):
        row = db.execute(
            "SELECT locked_until FROM throttle WHERE key = ?", (key,)
        ).fetchone()
        if row and row["locked_until"] and row["locked_until"] > now:
            return True
    return False


def record_failure(db, username: str, ip: str):
    cfg = current_app.config
    now = _now()
    window = timedelta(minutes=cfg["THROTTLE_WINDOW_MINUTES"])
    pair_key, ip_key = _keys(username, ip)
    for key, limit in ((pair_key, cfg["THROTTLE_MAX_FAILS"]), (ip_key, cfg["THROTTLE_IP_MAX_FAILS"])):
        row = db.execute(
            "SELECT fails, first_fail_at FROM throttle WHERE key = ?", (key,)
        ).fetchone()
        if row is None or datetime.fromisoformat(row["first_fail_at"]) < now - window:
            fails = 1
            db.execute(
                "INSERT INTO throttle (key, fails, first_fail_at, locked_until)"
                " VALUES (?, 1, ?, NULL)"
                " ON CONFLICT(key) DO UPDATE SET fails = 1, first_fail_at = ?, locked_until = NULL",
                (key, now.isoformat(), now.isoformat()),
            )
        else:
            fails = row["fails"] + 1
            db.execute("UPDATE throttle SET fails = ? WHERE key = ?", (fails, key))
        if fails >= limit:
            locked_until = (now + timedelta(minutes=cfg["THROTTLE_LOCK_MINUTES"])).isoformat()
            db.execute(
                "UPDATE throttle SET locked_until = ? WHERE key = ?", (locked_until, key)
            )
    db.commit()


def clear(db, username: str, ip: str):
    pair_key, _ = _keys(username, ip)
    db.execute("DELETE FROM throttle WHERE key = ?", (pair_key,))
    db.commit()
