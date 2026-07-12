import functools
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint, current_app, flash, g, redirect, render_template, request,
    session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit, mailer, throttle
from .db import get_db
from .security import (
    ensure_csrf_token, new_wrapped_dek, rewrap_dek, session_vault, unwrap_dek,
)

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
INVALID_LOGIN_MSG = "Invalid username or password."
LOCKED_MSG = "Too many failed attempts. Try again later."
RESET_SENT_MSG = "If an account exists with that email, a reset link has been sent."


def password_policy_error(password: str):
    if len(password) < current_app.config["MIN_MASTER_PASSWORD_LEN"]:
        return (
            f"Master password must be at least "
            f"{current_app.config['MIN_MASTER_PASSWORD_LEN']} characters."
        )
    if len(password) > 256:
        return "Master password must be at most 256 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Master password must include at least one letter and one digit."
    return None


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("auth.login"))
        g.user_id = session["user_id"]
        return view(**kwargs)
    return wrapped


def unlocked_required(view):
    """Requires a live vault session (login + unexpired idle timer). API
    routes get a 401 JSON body; pages get redirected to login."""
    @functools.wraps(view)
    def wrapped(**kwargs):
        ttl = current_app.config["VAULT_TIMEOUT_MINUTES"] * 60
        entry = session_vault.get(session.get("vault_token", ""), ttl)
        if entry is None or "user_id" not in session or entry[0] != session["user_id"]:
            session.pop("vault_token", None)
            if request.path.startswith("/api/"):
                return {"error": "vault locked"}, 401
            flash("Vault locked. Please log in again.")
            return redirect(url_for("auth.login"))
        g.user_id, g.dek = entry
        return view(**kwargs)
    return wrapped


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _start_session(user_id: int, username: str, dek: bytes):
    """Fresh session on every privilege change (fixation defense)."""
    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    ttl = current_app.config["VAULT_TIMEOUT_MINUTES"] * 60
    session["vault_token"] = session_vault.create(user_id, dek, ttl)
    ensure_csrf_token()


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = None
        if not USERNAME_RE.match(username):
            error = "Username must be 3-32 characters: letters, digits, . _ -"
        elif not EMAIL_RE.match(email):
            error = "Enter a valid email address."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            error = password_policy_error(password)

        if error is None:
            db = get_db()
            exists = db.execute(
                "SELECT 1 FROM users WHERE username = ? OR email = ?",
                (username, email),
            ).fetchone()
            if exists:
                error = "Username or email is already registered."
            else:
                _, kek_salt, dek_wrapped = new_wrapped_dek(password)
                cur = db.execute(
                    "INSERT INTO users (username, email, auth_hash, kek_salt,"
                    " dek_wrapped, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        username,
                        email,
                        generate_password_hash(
                            password, method=current_app.config["PASSWORD_HASH_METHOD"]
                        ),
                        kek_salt,
                        dek_wrapped,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                audit.record(db, cur.lastrowid, "account_created")
                db.commit()
                flash("Account created. Log in to unlock your vault.")
                return redirect(url_for("auth.login"))

        flash(error)
    return render_template("register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = _client_ip()
        db = get_db()

        if throttle.is_locked(db, username, ip):
            flash(LOCKED_MSG)
            return redirect(url_for("auth.login"))

        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None:
            # Level timing with the real-user path so username existence
            # is not observable from response time.
            check_password_hash(current_app.config["_DUMMY_AUTH_HASH"], password)
            throttle.record_failure(db, username, ip)
            flash(INVALID_LOGIN_MSG)
            return redirect(url_for("auth.login"))

        if not check_password_hash(user["auth_hash"], password):
            throttle.record_failure(db, username, ip)
            flash(INVALID_LOGIN_MSG)
            return redirect(url_for("auth.login"))

        dek = unwrap_dek(password, user["kek_salt"], user["dek_wrapped"])
        throttle.clear(db, username, ip)
        _start_session(user["id"], user["username"], dek)
        db.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), user["id"]),
        )
        audit.record(db, user["id"], "login")
        db.commit()
        return redirect(url_for("vault.dashboard"))

    return render_template("login.html")


@bp.route("/logout", methods=("POST",))
def logout():
    token = session.get("vault_token", "")
    user_id = session.get("user_id")
    session_vault.drop(token)
    if user_id is not None:
        db = get_db()
        audit.record(db, user_id, "logout")
        db.commit()
    session.clear()
    flash("Logged out. Vault locked.")
    return redirect(url_for("vault.home"))


@bp.route("/account")
@login_required
def account():
    return render_template("account.html")


@bp.route("/account/change-password", methods=("POST",))
@login_required
def change_password():
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (g.user_id,)).fetchone()

    error = None
    if not check_password_hash(user["auth_hash"], current):
        error = "Current password is incorrect."
    elif new != confirm:
        error = "New passwords do not match."
    else:
        error = password_policy_error(new)
    if error:
        flash(error)
        return redirect(url_for("auth.account"))

    dek = unwrap_dek(current, user["kek_salt"], user["dek_wrapped"])
    kek_salt, dek_wrapped = rewrap_dek(dek, new)
    db.execute(
        "UPDATE users SET auth_hash = ?, kek_salt = ?, dek_wrapped = ? WHERE id = ?",
        (
            generate_password_hash(new, method=current_app.config["PASSWORD_HASH_METHOD"]),
            kek_salt,
            dek_wrapped,
            g.user_id,
        ),
    )
    audit.record(db, g.user_id, "password_changed")
    db.commit()
    session_vault.drop_user(g.user_id)
    _start_session(user["id"], user["username"], dek)
    flash("Password changed. Your vault was re-encrypted under the new password.")
    return redirect(url_for("auth.account"))


@bp.route("/forgot-password", methods=("GET", "POST"))
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(
                minutes=current_app.config["RESET_TOKEN_MINUTES"]
            )
            db.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user["id"],))
            db.execute(
                "INSERT INTO reset_tokens (token_hash, user_id, expires_at)"
                " VALUES (?, ?, ?)",
                (_hash_token(token), user["id"], expires.isoformat()),
            )
            audit.record(db, user["id"], "reset_requested")
            db.commit()
            link = url_for("auth.reset_password", token=token, _external=True)
            mailer.send_reset_link(user["email"], link)
        flash(RESET_SENT_MSG)
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html")


@bp.route("/reset-password/<token>", methods=("GET", "POST"))
def reset_password(token):
    db = get_db()
    row = db.execute(
        "SELECT * FROM reset_tokens WHERE token_hash = ?", (_hash_token(token),)
    ).fetchone()
    if row is None or row["expires_at"] < datetime.now(timezone.utc).isoformat():
        flash("Reset link is invalid or has expired.")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        error = None
        if password != confirm:
            error = "Passwords do not match."
        elif request.form.get("confirm_purge") != "yes":
            error = "You must acknowledge that stored credentials will be erased."
        else:
            error = password_policy_error(password)
        if error:
            flash(error)
            return render_template("reset_password.html", token=token)

        # The vault key is wrapped by the old password; without it the
        # ciphertext is unrecoverable, so erase it explicitly rather than
        # leaving undecryptable rows behind.
        purged = db.execute(
            "DELETE FROM credentials WHERE user_id = ?", (row["user_id"],)
        ).rowcount
        _, kek_salt, dek_wrapped = new_wrapped_dek(password)
        db.execute(
            "UPDATE users SET auth_hash = ?, kek_salt = ?, dek_wrapped = ? WHERE id = ?",
            (
                generate_password_hash(
                    password, method=current_app.config["PASSWORD_HASH_METHOD"]
                ),
                kek_salt,
                dek_wrapped,
                row["user_id"],
            ),
        )
        db.execute("DELETE FROM reset_tokens WHERE user_id = ?", (row["user_id"],))
        audit.record(db, row["user_id"], "password_reset", f"vault purged ({purged} credentials)")
        db.commit()
        session_vault.drop_user(row["user_id"])
        flash("Password reset. Your previous credentials were erased.")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
