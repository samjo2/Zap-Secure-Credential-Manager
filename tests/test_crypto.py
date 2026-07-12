import pytest
from cryptography.exceptions import InvalidTag

from zap.security import (
    credential_aad, decrypt_secret, encrypt_secret, new_wrapped_dek,
    rewrap_dek, unwrap_dek,
)


def test_dek_roundtrip_and_wrong_password(app):
    with app.app_context():
        dek, salt, wrapped = new_wrapped_dek("master-password-9")
        assert unwrap_dek("master-password-9", salt, wrapped) == dek
        with pytest.raises(InvalidTag):
            unwrap_dek("wrong-password-9", salt, wrapped)


def test_rewrap_preserves_dek(app):
    with app.app_context():
        dek, _, _ = new_wrapped_dek("old-password-99")
        salt, wrapped = rewrap_dek(dek, "new-password-99")
        assert unwrap_dek("new-password-99", salt, wrapped) == dek


def test_wrapped_dek_is_never_plaintext(app):
    with app.app_context():
        dek, _, wrapped = new_wrapped_dek("master-password-9")
        assert dek not in wrapped


def test_aad_binds_ciphertext_to_owner_and_credential(app):
    """Swapping an encrypted blob onto another user's row or another
    credential id must fail to decrypt, even with the right key."""
    with app.app_context():
        dek, _, _ = new_wrapped_dek("master-password-9")
        blob = encrypt_secret(dek, b"payload", credential_aad(1, "cred-a"))
        assert decrypt_secret(dek, blob, credential_aad(1, "cred-a")) == b"payload"
        with pytest.raises(InvalidTag):
            decrypt_secret(dek, blob, credential_aad(2, "cred-a"))
        with pytest.raises(InvalidTag):
            decrypt_secret(dek, blob, credential_aad(1, "cred-b"))


def test_nonces_are_unique_per_encryption(app):
    with app.app_context():
        dek, _, _ = new_wrapped_dek("master-password-9")
        aad = credential_aad(1, "cred-a")
        blobs = {bytes(encrypt_secret(dek, b"same payload", aad)) for _ in range(20)}
        assert len(blobs) == 20
