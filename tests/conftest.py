import re

import pytest

from zap import create_app

DEFAULT_PASSWORD = "correct-horse-9-Battery"

# Weak KDF/hash parameters: tests exercise logic, not brute-force cost.
FAST_CRYPTO = {
    "SCRYPT_N": 2**4,
    "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000",
}

CSRF_RE = re.compile(r'name="csrf-token" content="([^"]+)"')


def make_app(tmp_path, **overrides):
    config = {
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "SECRET_KEY": "test-secret-key",
        **FAST_CRYPTO,
        **overrides,
    }
    return create_app(config)


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def actor(client):
    return Actor(client)


class Actor:
    """Test client wrapper that handles CSRF the way the real UI does:
    reads the token out of a rendered page and sends it back."""

    def __init__(self, client, ip=None):
        self.client = client
        self.extra = {"environ_base": {"REMOTE_ADDR": ip}} if ip else {}

    def csrf(self, path="/"):
        resp = self.client.get(path, follow_redirects=True, **self.extra)
        return CSRF_RE.search(resp.get_data(as_text=True)).group(1)

    def register(self, username="sam", email="sam@example.com",
                 password=DEFAULT_PASSWORD, confirm=None):
        return self.client.post(
            "/register",
            data={
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": confirm if confirm is not None else password,
                "csrf_token": self.csrf("/register"),
            },
            follow_redirects=True,
            **self.extra,
        )

    def login(self, username="sam", password=DEFAULT_PASSWORD):
        return self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": self.csrf("/login"),
            },
            follow_redirects=True,
            **self.extra,
        )

    def signup(self, username="sam", email="sam@example.com",
               password=DEFAULT_PASSWORD):
        self.register(username, email, password)
        return self.login(username, password)

    def api(self, method, path, **kwargs):
        headers = kwargs.pop("headers", {})
        headers.setdefault("X-CSRF-Token", self.csrf())
        return self.client.open(
            path, method=method, headers=headers, **kwargs, **self.extra
        )

    def add_credential(self, service="GitHub", username="octocat",
                       password="hunter2-secret", site="github.com", notes=""):
        return self.api(
            "POST",
            "/api/credentials",
            json={
                "service": service,
                "username": username,
                "password": password,
                "site": site,
                "notes": notes,
            },
        )
