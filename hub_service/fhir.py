#!/usr/bin/env python3
"""
SMART service authentication for a FHIR endpoint with the Hub
- Asymmetric authentication
"""

import os
import time
import subprocess
import json
import secrets
from functools import wraps
from flask import Flask, Response, make_response, redirect, request, session
from jupyterhub.services.auth import HubOAuth
from dataclasses import dataclass
import requests
from urllib.parse import urlencode
import jwt
from common.config import SMART

prefix = os.environ.get("JUPYTERHUB_SERVICE_PREFIX", "/")
auth = HubOAuth(api_token=os.environ["JUPYTERHUB_API_TOKEN"], cache_max_age=60)
app = Flask(__name__)
# encryption key for session cookies
app.secret_key = secrets.token_bytes(32)
smart_broadcast = ".well-known/smart-configuration"


@dataclass
class OAuthState:
    state_id: str
    extra_state: dict[str]
    code: str | None = None


def get_jwks(key_file: str = "jwtRS256.key", key_id: str = "1") -> str:
    try:
        with open(key_file + ".pub", "r") as f:
            public_key = f.read()
    except FileNotFoundError:
        print(f"Public key file {key_file}.pub not found. Generating new key pair")

        # Generate new RSA key pair using OpenSSL
        subprocess.call(["openssl", "genrsa", "-out", key_file, "2048"])
        subprocess.call(
            ["openssl", "rsa", "-in", key_file, "-pubout", "-out", f"{key_file}.pub"]
        )
        subprocess.call(
            [
                "ssh-keygen",
                "-t",
                "rsa",
                "-b",
                "4096",
                "-m",
                "PEM",
                "-f",
                key_file,
                "-q",
                "-N",
                "",
            ]
        )
        with open(key_file + ".pub", "rb") as f:
            public_key = f.read()

    alg = jwt.get_algorithm_by_name("RS256")
    key = alg.prepare_key(public_key)
    jwk = alg.to_jwk(key, as_dict=True)
    jwk.update({"alg": "RS256", "kid": key_id})
    jwks_smart = {"keys": [jwk]}
    jwks_smart_str = json.dumps(jwks_smart, indent=2)
    # Printing the JWKS to console to include in the SMART-on-FHIR launch
    print(jwks_smart_str)
    return jwks_smart_str


get_jwks()


def generate_jwt(key_file: str = "jwtRS256.key", key_id: str = "1") -> str:
    config = SMART(**session.get("smart_config"))
    jwt_dict = {
        "iss": config.client_id,
        "sub": config.client_id,
        "aud": config.token_url,
        "jti": "jwt_id",
        "exp": int(time.time() + 3600),
    }
    headers = {"kid": key_id}
    with open(key_file, "rb") as f:
        private_key = f.read()
    return jwt.encode(jwt_dict, private_key, "RS256", headers)


def generate_state(next_url=None) -> OAuthState:
    state_id = secrets.token_urlsafe(16)
    state = {
        "next_url": next_url,
        "httponly": True,
        "max_age": 600,
    }
    return OAuthState(state_id, state)


def token_for_code(code: str):
    config = SMART(**session.get("smart_config"))
    data = dict(
        client_id=config.client_id,
        grant_type="authorization_code",
        code=code,
        redirect_uri=config.base_url + "oauth_callback",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion=generate_jwt(),
    )
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_reply = requests.post(config.token_url, data=data, headers=headers)
    return token_reply.json()["access_token"]


def authenticated(f):
    """Decorator for authenticating with the Hub via OAuth"""

    @wraps(f)
    def decorated(*args, **kwargs):
        if token := session.get("token"):
            return f(token, *args, **kwargs)

        else:
            # redirect to login url on failed auth
            session["smart_config"] = SMART.from_url(
                request.args.get("iss"), request.base_url
            )
            state = generate_state(next_url=request.path)
            from_redirect = make_response(start_oauth_flow(state_id=state.state_id))
            from_redirect.set_cookie(
                "state_id", state.state_id, secure=True, httponly=True
            )
            from_redirect.set_cookie("next_url", state.extra_state["next_url"])
            return from_redirect

    return decorated


def start_oauth_flow(state_id: str, scopes: list[str] | None = None):
    config = session.get("smart_config")
    redirect_uri = config.base_url + "oauth_callback"
    scopes = scopes or config.scopes
    headers = {
        "aud": config.fhir_url,
        "state": state_id,
        "redirect_uri": redirect_uri,
        "launch": request.args.get("launch"),
        "client_id": config.client_id,
        "response_type": "code",
        "scopes": " ".join(scopes),
    }
    auth_url = f"{config.auth_url}?{urlencode(headers)}"
    response = redirect(auth_url)
    return response


@app.route(prefix)
@authenticated
def fetch_data(token: str):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/fhir+json",
        "User-Agent": "JupyterHub",
    }
    url = f"{SMART(**session['smart_config']).fhir_url}/Condition"  # Endpoint with data
    f = requests.get(url, headers=headers)
    return Response(f.text, mimetype="application/json")


@app.route(prefix + "oauth_callback")
def callback():
    state_id = request.cookies.get("state_id")
    next_url = request.cookies.get("next_url")

    if error := request.args.get("error", False):
        return Response(
            f"Error in OAuth: {request.args.get('error_description', error)}",
            status=400,
        )
    code = request.args.get("code")
    if not code:
        return Response("OAuth callback made without a token", status=400)
    arg_state = request.args.get("state", None)
    if arg_state != state_id:
        return Response("OAuth state does not match. Try logging in again.", status=403)

    token = token_for_code(code)
    session["token"] = token
    return make_response(redirect(next_url))
