import json
import secrets
import string
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Blueprint, g, jsonify, redirect, render_template, request, session, url_for

from . import audit
from .auth import login_required, unlocked_required
from .db import get_db
from .security import credential_aad, decrypt_secret, encrypt_secret

bp = Blueprint("vault", __name__)

FIELD_LIMITS = {"service": 128, "username": 256, "password": 1024, "site": 256, "notes": 4096}


@bp.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("vault.dashboard"))
    return render_template("home.html")


@bp.route("/vault")
@unlocked_required
def dashboard():
    return render_template("dashboard.html")


@bp.route("/audit")
@login_required
def audit_page():
    db = get_db()
    return render_template(
        "audit.html",
        entries=audit.entries_for(db, g.user_id),
        chain_ok=audit.verify_chain(db, g.user_id),
    )


@bp.route("/api/credentials")
@unlocked_required
def list_credentials():
    db = get_db()
    rows = db.execute(
        "SELECT id, service, site, secret, updated_at FROM credentials"
        " WHERE user_id = ? ORDER BY service COLLATE NOCASE",
        (g.user_id,),
    ).fetchall()
    items = []
    for row in rows:
        data = _open_secret(row)
        items.append(
            {
                "id": row["id"],
                "service": row["service"],
                "site": row["site"],
                "username": data["username"],
                "has_notes": bool(data.get("notes")),
                "updated_at": row["updated_at"],
            }
        )
    return jsonify(items)


@bp.route("/api/credentials", methods=("POST",))
@unlocked_required
def add_credential():
    fields, error = _read_fields()
    if error:
        return jsonify({"error": error}), 400
    db = get_db()
    cred_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO credentials (id, user_id, service, site, secret, created_at,"
        " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (cred_id, g.user_id, fields["service"], fields["site"],
         _seal_secret(cred_id, fields), now, now),
    )
    audit.record(db, g.user_id, "credential_added", fields["service"])
    db.commit()
    return jsonify({"id": cred_id}), 201


@bp.route("/api/credentials/<cred_id>", methods=("PUT",))
@unlocked_required
def update_credential(cred_id):
    fields, error = _read_fields()
    if error:
        return jsonify({"error": error}), 400
    db = get_db()
    row = _owned_row(db, cred_id)
    if row is None:
        return jsonify({"error": "not found"}), 404
    db.execute(
        "UPDATE credentials SET service = ?, site = ?, secret = ?, updated_at = ?"
        " WHERE id = ?",
        (fields["service"], fields["site"], _seal_secret(cred_id, fields),
         datetime.now(timezone.utc).isoformat(), cred_id),
    )
    audit.record(db, g.user_id, "credential_updated", fields["service"])
    db.commit()
    return jsonify({"id": cred_id})


@bp.route("/api/credentials/<cred_id>", methods=("DELETE",))
@unlocked_required
def delete_credential(cred_id):
    db = get_db()
    row = _owned_row(db, cred_id)
    if row is None:
        return jsonify({"error": "not found"}), 404
    db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    audit.record(db, g.user_id, "credential_deleted", row["service"])
    db.commit()
    return jsonify({"deleted": cred_id})


@bp.route("/api/credentials/<cred_id>/reveal")
@unlocked_required
def reveal_credential(cred_id):
    db = get_db()
    row = _owned_row(db, cred_id)
    if row is None:
        return jsonify({"error": "not found"}), 404
    data = _open_secret(row)
    return jsonify(
        {"username": data["username"], "password": data["password"],
         "notes": data.get("notes", "")}
    )


@bp.route("/api/fill")
@unlocked_required
def fill():
    """Best credential for a domain, for the browser extension. Matches the
    stored site exactly or as a parent domain of the requested host."""
    host = _normalize_site(request.args.get("domain", ""))
    if not host:
        return jsonify({"error": "domain required"}), 400
    db = get_db()
    rows = db.execute(
        "SELECT id, service, site, secret FROM credentials WHERE user_id = ?"
        " AND site IS NOT NULL AND site != ''",
        (g.user_id,),
    ).fetchall()
    best = None
    for row in rows:
        if host == row["site"] or host.endswith("." + row["site"]):
            if best is None or len(row["site"]) > len(best["site"]):
                best = row
    if best is None:
        return jsonify({"error": "no credential for domain"}), 404
    data = _open_secret(best)
    return jsonify(
        {"service": best["service"], "username": data["username"],
         "password": data["password"]}
    )


@bp.route("/api/generate-password")
def generate_password():
    try:
        length = int(request.args.get("length", 20))
    except ValueError:
        return jsonify({"error": "length must be an integer"}), 400
    length = max(8, min(length, 128))
    symbols = request.args.get("symbols", "1") != "0"
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*-_=+?")
    alphabet = "".join(pools)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in password) for pool in pools):
            return jsonify({"password": password, "length": length})


def _read_fields():
    src = request.get_json(silent=True) or request.form
    fields = {}
    for name, limit in FIELD_LIMITS.items():
        value = (src.get(name) or "").strip()
        if len(value) > limit:
            return None, f"{name} must be at most {limit} characters"
        fields[name] = value
    if not fields["service"]:
        return None, "service is required"
    if not fields["password"]:
        return None, "password is required"
    fields["site"] = _normalize_site(fields["site"])
    return fields, None


def _seal_secret(cred_id: str, fields: dict) -> bytes:
    payload = json.dumps(
        {"username": fields["username"], "password": fields["password"],
         "notes": fields["notes"]}
    ).encode()
    return encrypt_secret(g.dek, payload, credential_aad(g.user_id, cred_id))


def _open_secret(row) -> dict:
    plaintext = decrypt_secret(
        g.dek, row["secret"], credential_aad(g.user_id, row["id"])
    )
    return json.loads(plaintext)


def _owned_row(db, cred_id: str):
    return db.execute(
        "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
        (cred_id, g.user_id),
    ).fetchone()


def _normalize_site(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    if "//" not in value:
        value = "//" + value
    host = urlsplit(value).hostname or ""
    return host.removeprefix("www.")
