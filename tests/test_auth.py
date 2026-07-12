import sqlite3

from tests.conftest import Actor, DEFAULT_PASSWORD, make_app


def test_register_login_logout(actor, client):
    resp = actor.register()
    assert b"Account created" in resp.data

    resp = actor.login()
    assert b"Your vault" in resp.data

    resp = client.post(
        "/logout", data={"csrf_token": actor.csrf()}, follow_redirects=True
    )
    assert b"Vault locked" in resp.data
    assert client.get("/vault", follow_redirects=True).request.path == "/login"


def test_register_rejects_weak_or_mismatched_passwords(actor):
    assert b"at least 12 characters" in actor.register(password="Short1x").data
    assert b"letter and one digit" in actor.register(password="nodigitshere!!").data
    assert b"do not match" in actor.register(confirm="different-9-Pass").data


def test_register_rejects_duplicates(actor):
    actor.register()
    assert b"already registered" in actor.register(email="other@example.com").data
    assert b"already registered" in actor.register(username="other").data


def test_login_error_is_uniform_for_unknown_user_and_wrong_password(actor):
    actor.register()
    wrong_password = actor.login(password="Wrong-password-9").data
    unknown_user = actor.login(username="ghost", password="Wrong-password-9").data
    assert b"Invalid username or password." in wrong_password
    assert b"Invalid username or password." in unknown_user


def test_throttle_locks_attacker_ip_but_not_victim(app):
    victim = Actor(app.test_client(), ip="10.0.0.1")
    attacker = Actor(app.test_client(), ip="10.0.0.66")
    victim.register()

    for _ in range(app.config["THROTTLE_MAX_FAILS"]):
        attacker.login(password="Wrong-password-9")
    assert b"Too many failed attempts" in attacker.login().data

    # Same username, real password, victim's own IP: unaffected.
    assert b"Your vault" in victim.login().data


def test_vault_times_out_and_relocks(tmp_path):
    app = make_app(tmp_path, VAULT_TIMEOUT_MINUTES=0)
    actor = Actor(app.test_client())
    actor.signup()
    resp = actor.client.get("/api/credentials")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "vault locked"


def test_change_password_keeps_vault(actor, client):
    actor.signup()
    cred_id = actor.add_credential(password="pw-to-survive-9").get_json()["id"]

    new_password = "brand-new-master-99"
    resp = client.post(
        "/account/change-password",
        data={
            "current_password": DEFAULT_PASSWORD,
            "new_password": new_password,
            "confirm_password": new_password,
            "csrf_token": actor.csrf(),
        },
        follow_redirects=True,
    )
    assert b"re-encrypted" in resp.data

    client.post("/logout", data={"csrf_token": actor.csrf()}, follow_redirects=True)
    assert b"Your vault" in actor.login(password=new_password).data
    revealed = client.get(f"/api/credentials/{cred_id}/reveal").get_json()
    assert revealed["password"] == "pw-to-survive-9"


def test_reset_flow_purges_vault_and_requires_consent(actor, client, app, monkeypatch):
    links = []
    monkeypatch.setattr("zap.mailer.send_reset_link", lambda email, link: links.append(link))

    actor.signup()
    actor.add_credential()
    client.post("/logout", data={"csrf_token": actor.csrf()}, follow_redirects=True)

    client.post(
        "/forgot-password",
        data={"email": "sam@example.com", "csrf_token": actor.csrf("/forgot-password")},
        follow_redirects=True,
    )
    assert len(links) == 1
    reset_path = "/reset-password/" + links[0].rsplit("/", 1)[1]

    new_password = "reset-master-pass-77"
    data = {
        "password": new_password,
        "confirm_password": new_password,
        "csrf_token": actor.csrf(reset_path),
    }
    resp = client.post(reset_path, data=data, follow_redirects=True)
    assert b"must acknowledge" in resp.data

    data["confirm_purge"] = "yes"
    resp = client.post(reset_path, data=data, follow_redirects=True)
    assert b"previous credentials were erased" in resp.data

    # Token is single-use.
    resp = client.get(reset_path, follow_redirects=True)
    assert b"invalid or has expired" in resp.data

    assert b"Your vault" in actor.login(password=new_password).data
    assert client.get("/api/credentials").get_json() == []


def test_expired_reset_token_rejected(tmp_path, monkeypatch):
    app = make_app(tmp_path, RESET_TOKEN_MINUTES=-1)
    actor = Actor(app.test_client())
    links = []
    monkeypatch.setattr("zap.mailer.send_reset_link", lambda email, link: links.append(link))
    actor.register()
    actor.client.post(
        "/forgot-password",
        data={"email": "sam@example.com", "csrf_token": actor.csrf("/forgot-password")},
    )
    reset_path = "/reset-password/" + links[0].rsplit("/", 1)[1]
    resp = actor.client.get(reset_path, follow_redirects=True)
    assert b"invalid or has expired" in resp.data


def test_forgot_password_response_is_uniform(actor):
    actor.register()
    known = actor.client.post(
        "/forgot-password",
        data={"email": "sam@example.com", "csrf_token": actor.csrf("/forgot-password")},
        follow_redirects=True,
    )
    unknown = actor.client.post(
        "/forgot-password",
        data={"email": "ghost@example.com", "csrf_token": actor.csrf("/forgot-password")},
        follow_redirects=True,
    )
    assert b"If an account exists" in known.data
    assert b"If an account exists" in unknown.data


def test_reset_tokens_stored_hashed(actor, app, monkeypatch):
    links = []
    monkeypatch.setattr("zap.mailer.send_reset_link", lambda email, link: links.append(link))
    actor.register()
    actor.client.post(
        "/forgot-password",
        data={"email": "sam@example.com", "csrf_token": actor.csrf("/forgot-password")},
    )
    token = links[0].rsplit("/", 1)[1]
    con = sqlite3.connect(app.config["DATABASE"])
    stored = con.execute("SELECT token_hash FROM reset_tokens").fetchone()[0]
    con.close()
    assert token not in stored
