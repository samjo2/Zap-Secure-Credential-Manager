import sqlite3

from tests.conftest import Actor, DEFAULT_PASSWORD


def test_credential_crud_roundtrip(actor):
    actor.signup()

    created = actor.add_credential(notes="2FA backup: 1234")
    assert created.status_code == 201
    cred_id = created.get_json()["id"]

    items = actor.client.get("/api/credentials").get_json()
    assert len(items) == 1
    assert items[0]["service"] == "GitHub"
    assert items[0]["username"] == "octocat"
    assert items[0]["has_notes"] is True
    assert "password" not in items[0]

    revealed = actor.client.get(f"/api/credentials/{cred_id}/reveal").get_json()
    assert revealed["password"] == "hunter2-secret"
    assert revealed["notes"] == "2FA backup: 1234"

    updated = actor.api(
        "PUT",
        f"/api/credentials/{cred_id}",
        json={"service": "GitHub", "username": "octocat",
              "password": "new-password-9", "site": "github.com", "notes": ""},
    )
    assert updated.status_code == 200
    revealed = actor.client.get(f"/api/credentials/{cred_id}/reveal").get_json()
    assert revealed["password"] == "new-password-9"

    deleted = actor.api("DELETE", f"/api/credentials/{cred_id}")
    assert deleted.status_code == 200
    assert actor.client.get("/api/credentials").get_json() == []


def test_secrets_are_ciphertext_at_rest(actor, app):
    actor.signup()
    plaintext = "super-secret-password-42"
    actor.add_credential(password=plaintext, notes="secret note text")

    # Dispositive check: read the raw database file, not the API.
    raw = open(app.config["DATABASE"], "rb").read()
    assert plaintext.encode() not in raw
    assert b"secret note text" not in raw
    assert b"octocat" not in raw

    con = sqlite3.connect(app.config["DATABASE"])
    secret_blob = con.execute("SELECT secret FROM credentials").fetchone()[0]
    con.close()
    assert plaintext.encode() not in secret_blob


def test_master_password_never_stored(actor, app):
    actor.signup()
    raw = open(app.config["DATABASE"], "rb").read()
    assert DEFAULT_PASSWORD.encode() not in raw


def test_users_cannot_read_each_others_credentials(app):
    alice = Actor(app.test_client())
    bob = Actor(app.test_client())
    alice.signup("alice", "alice@example.com")
    bob.signup("bob", "bob@example.com")

    cred_id = alice.add_credential().get_json()["id"]

    assert bob.client.get("/api/credentials").get_json() == []
    assert bob.client.get(f"/api/credentials/{cred_id}/reveal").status_code == 404
    assert bob.api("DELETE", f"/api/credentials/{cred_id}").status_code == 404
    # And the row is still there for alice.
    assert len(alice.client.get("/api/credentials").get_json()) == 1


def test_api_requires_unlocked_vault(client):
    assert client.get("/api/credentials").status_code == 401
    assert client.get("/api/fill?domain=github.com").status_code == 401


def test_validation_rejects_missing_fields(actor):
    actor.signup()
    resp = actor.api("POST", "/api/credentials",
                     json={"service": "", "password": "x-9"})
    assert resp.status_code == 400
    resp = actor.api("POST", "/api/credentials",
                     json={"service": "X", "password": ""})
    assert resp.status_code == 400
    resp = actor.api("POST", "/api/credentials",
                     json={"service": "X" * 200, "password": "x-9"})
    assert resp.status_code == 400


def test_fill_matches_domain_and_subdomain(actor):
    actor.signup()
    actor.add_credential(site="https://www.github.com/login")

    for domain in ("github.com", "gist.github.com", "WWW.GITHUB.COM"):
        resp = actor.client.get(f"/api/fill?domain={domain}")
        assert resp.status_code == 200, domain
        assert resp.get_json()["username"] == "octocat"

    assert actor.client.get("/api/fill?domain=evil-github.com").status_code == 404
    assert actor.client.get("/api/fill?domain=example.com").status_code == 404


def test_generate_password_options(client):
    data = client.get("/api/generate-password?length=32").get_json()
    assert len(data["password"]) == 32

    data = client.get("/api/generate-password?length=16&symbols=0").get_json()
    assert data["password"].isalnum()

    # Bounds are clamped, not errors.
    assert len(client.get("/api/generate-password?length=4").get_json()["password"]) == 8

    passwords = {client.get("/api/generate-password").get_json()["password"] for _ in range(5)}
    assert len(passwords) == 5
