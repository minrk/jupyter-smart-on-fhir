import pytest
from flask import session
from jupyter_smart_on_fhir.hub_service import (
    app,
    set_encrypted_cookie,
    get_encrypted_cookie,
)


@pytest.mark.parametrize(
    "key,value",
    [
        ("test_key", "test_value"),
        ("user_id", "12345"),
        ("session_token", "abcdef123456"),
        ("empty_value", ""),
        ("special_chars", "!@#$%^&*()_+"),
    ],
)
def test_encrypted_cookie(key, value):
    with app.test_request_context():
        session.clear()
        # Set the encrypted cookie
        set_encrypted_cookie(key, value)
        # Verify the cookie is in the session and encrypted
        assert key in session
        assert session[key] != value
        # Get the decrypted cookie value
        decrypted_value = get_encrypted_cookie(key)
        # Verify the decrypted value matches the original
        assert decrypted_value == value


def test_get_nonexistent_cookie():
    with app.test_request_context():
        session.clear()
        value = get_encrypted_cookie("nonexistent_key")
        assert value is None


def test_invalid_token():
    with app.test_request_context():
        session.clear()
        session["invalid_key"] = b"invalid_token"
        value = get_encrypted_cookie("invalid_key")
        assert value is None
