import pytest
from flask import session
from jupyter_smart_on_fhir.auth import get_jwks_from_key
from jupyter_smart_on_fhir.hub_service import (
    create_app,
    set_encrypted_cookie,
    get_encrypted_cookie,
    prefix,
    token_for_code,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
import requests
from conftest import SandboxConfig
from urllib import parse


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("keys")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_name = "jwtRS256.key"
    private_key_path = tmp_path / key_name
    public_key_path = tmp_path / f"{key_name}.pub"
    private_key_path.write_bytes(private_pem)
    public_key_path.write_bytes(public_pem)
    return {"SSH_KEY_PATH": str(private_key_path), "SSH_KEY_ID": "test_key"}


@pytest.fixture(scope="function")
def mock_env(monkeypatch, keys):
    env = {
        "JUPYTERHUB_API_TOKEN": os.getenv("JUPYTERHUB_API_TOKEN", "API_TOKEN"),
        "CLIENT_ID": os.getenv("CLIENT_ID", "CLIENT_ID"),
        "SCOPES": os.getenv("SCOPES", "launch profile patient/*.*"),
    } | keys
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env


@pytest.fixture(scope="function")
def test_app(mock_env):
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture(scope="function")
def asymmetric_auth(keys):
    jwks = get_jwks_from_key(keys["SSH_KEY_PATH"], keys["SSH_KEY_ID"])
    return SandboxConfig(client_id=os.environ["CLIENT_ID"], jwks=jwks, client_type=2)


@pytest.fixture(scope="function")
def client(test_app):
    return test_app.test_client()


def test_ehr_launch(client):
    response = client.get("/?token=hello")
    assert response.status_code == 400


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
def test_encrypted_cookie(test_app, key, value):
    with test_app.test_request_context():
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


def test_get_nonexistent_cookie(test_app):
    with test_app.test_request_context():
        session.clear()
        value = get_encrypted_cookie("nonexistent_key")
        assert value is None


def test_invalid_token(test_app):
    with test_app.test_request_context():
        session.clear()
        session["invalid_key"] = b"invalid_token"
        value = get_encrypted_cookie("invalid_key")
        assert value is None


def test_access_sandbox(sandbox):
    f = requests.get(sandbox)
    print(f.status_code, f.text)
    assert f.status_code == 200


def test_to_auth_url(sandbox, client, asymmetric_auth):
    # start with oauth flow
    query = {"iss": f"{sandbox}/v/r4/fhir", "launch": asymmetric_auth.get_launch_code()}
    scopes = ["launch", "profile"]
    os.environ["SCOPES"] = " ".join(scopes)
    # set up test context
    with client.application.test_request_context():
        # Launch request from sandbox with given settings
        response = client.get(f"/?{parse.urlencode(query)}")
        # Expecting a redirect to the login page
        assert response.status_code == 302

        auth_url = response.headers["Location"]
        # Ensure auth url has correct domain and scopes
        assert auth_url.startswith(sandbox)
        assert "+".join(scopes) in auth_url

        # Check if auth_url passes strict client validation and provides code
        f = requests.get(auth_url, allow_redirects=False)
        assert f.status_code == 302

        callback_url = f.headers["Location"]
        assert "code" in callback_url
        assert prefix + "oauth_callback" in callback_url
        parsed_url = parse.urlparse(callback_url)
        qs = parse.parse_qs(parsed_url.query)
        code = qs["code"][0]
        # Test if we can exchange the code for a token with asymmetric validation
        # with client.session_transaction() as sess:
        #     sess["smart_config"] = {
        #         "base_url": sandbox,
        #         "fhir_url": f"{sandbox}/v/r4/fhir",
        #         "token_url": f"{sandbox}/token",
        #         "auth_url": f"{sandbox}/authorize",
        #         "scopes": scopes,
        #     }
        #     token = token_for_code(code)
        #     assert isinstance(token, str)
        # FIXME: The session seems to be empty, but only for this method. Don't understand why
