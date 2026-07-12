import logging
import os
import secrets
from pathlib import Path

from flask import Flask
from werkzeug.security import generate_password_hash

__version__ = "2.0.0"


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    # Reset links are emitted at INFO when SMTP is not configured; the
    # default WARNING level would silently swallow them.
    app.logger.setLevel(logging.INFO)

    app.config.from_mapping(
        DATABASE=os.environ.get("ZAP_DB_PATH")
        or os.path.join(app.instance_path, "zap.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("ZAP_HTTPS") == "1",
        MAX_CONTENT_LENGTH=64 * 1024,
        SCRYPT_N=2**14,
        SCRYPT_R=8,
        SCRYPT_P=1,
        SCRYPT_MAXMEM=64 * 1024 * 1024,
        PASSWORD_HASH_METHOD="scrypt",
        MIN_MASTER_PASSWORD_LEN=12,
        VAULT_TIMEOUT_MINUTES=int(os.environ.get("ZAP_VAULT_TIMEOUT_MINUTES", "15")),
        RESET_TOKEN_MINUTES=30,
        THROTTLE_MAX_FAILS=5,
        THROTTLE_IP_MAX_FAILS=20,
        THROTTLE_WINDOW_MINUTES=15,
        THROTTLE_LOCK_MINUTES=15,
        SMTP_HOST=os.environ.get("ZAP_SMTP_HOST"),
        SMTP_PORT=int(os.environ.get("ZAP_SMTP_PORT", "587")),
        SMTP_USERNAME=os.environ.get("ZAP_SMTP_USERNAME"),
        SMTP_PASSWORD=os.environ.get("ZAP_SMTP_PASSWORD"),
        SMTP_SENDER=os.environ.get("ZAP_SMTP_SENDER", "zap@localhost"),
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = (
            os.environ.get("ZAP_SECRET_KEY") or _load_or_create_secret(app)
        )
    app.config["_DUMMY_AUTH_HASH"] = generate_password_hash(
        "zap-timing-dummy", method=app.config["PASSWORD_HASH_METHOD"]
    )

    from . import auth, db, vault
    from .security import check_csrf, ensure_csrf_token

    db.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(vault.bp)
    app.before_request(check_csrf)
    app.context_processor(lambda: {"csrf_token": ensure_csrf_token()})

    @app.after_request
    def set_security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self';"
            " img-src 'self'; frame-ancestors 'none'; base-uri 'none';"
            " form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if resp.mimetype == "application/json":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


def _load_or_create_secret(app) -> str:
    """Persisted so sessions and audit HMACs survive restarts even without
    ZAP_SECRET_KEY set. File is local-only and never committed."""
    path = Path(app.instance_path) / "secret_key"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_hex(32)
    path.write_text(key)
    path.chmod(0o600)
    return key
