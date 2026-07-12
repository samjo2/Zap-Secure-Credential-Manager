import sqlite3


def test_csrf_required_on_forms(client):
    resp = client.post("/login", data={"username": "x", "password": "y"})
    assert resp.status_code == 400


def test_csrf_required_on_api(actor):
    actor.signup()
    resp = actor.client.post(
        "/api/credentials",
        json={"service": "X", "password": "y-9"},
    )
    assert resp.status_code == 400

    resp = actor.client.post(
        "/api/credentials",
        json={"service": "X", "password": "y-9"},
        headers={"X-CSRF-Token": "forged-token"},
    )
    assert resp.status_code == 400


def test_security_headers(client):
    resp = client.get("/")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_api_responses_not_cached(actor):
    actor.signup()
    resp = actor.client.get("/api/credentials")
    assert resp.headers["Cache-Control"] == "no-store"


def test_session_cookie_flags(actor):
    resp = actor.client.post(
        "/login",
        data={"username": "x", "password": "y", "csrf_token": actor.csrf("/login")},
    )
    cookie = resp.headers.get("Set-Cookie", "")
    assert cookie, "login must set a session cookie"
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_audit_chain_records_and_verifies(actor):
    actor.signup()
    actor.add_credential()
    page = actor.client.get("/audit").get_data(as_text=True)
    assert "Integrity verified" in page
    assert "credential added" in page
    assert "GitHub" in page


def test_audit_chain_detects_tampering(actor, app):
    actor.signup()
    actor.add_credential(service="Bank")
    actor.add_credential(service="Email")

    con = sqlite3.connect(app.config["DATABASE"])
    con.execute("UPDATE audit_log SET detail = 'Forged' WHERE detail = 'Bank'")
    con.commit()
    con.close()

    page = actor.client.get("/audit").get_data(as_text=True)
    assert "Integrity check FAILED" in page


def test_audit_chain_detects_deleted_history(actor, app):
    actor.signup()
    actor.add_credential(service="Bank")
    actor.add_credential(service="Email")

    con = sqlite3.connect(app.config["DATABASE"])
    con.execute("DELETE FROM audit_log WHERE detail = 'Bank'")
    con.commit()
    con.close()

    page = actor.client.get("/audit").get_data(as_text=True)
    assert "Integrity check FAILED" in page


def test_audit_log_contains_no_secrets(actor, app):
    actor.signup()
    actor.add_credential(password="top-secret-99")
    con = sqlite3.connect(app.config["DATABASE"])
    rows = con.execute("SELECT action || ' ' || detail FROM audit_log").fetchall()
    con.close()
    joined = " ".join(r[0] for r in rows)
    assert "top-secret-99" not in joined
