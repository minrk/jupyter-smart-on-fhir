#!/usr/bin/env python3
"""
smart service authentication for a FHIR endpoint with the Hub
- Asymmetric authentication
"""

import os
import json
import secrets
from functools import wraps
from flask import Flask, Response, make_response, redirect, request, session
from jupyterhub.services.auth import HubOAuth
from dataclasses import dataclass
import requests
from urllib.parse import urlencode

prefix = os.environ.get("JUPYTERHUB_SERVICE_PREFIX", "/")
auth = HubOAuth(api_token=os.environ["JUPYTERHUB_API_TOKEN"], cache_max_age=60)
app = Flask(__name__)
# encryption key for session cookies
app.secret_key = secrets.token_bytes(32)
smart_broadcast = ".well-known/smart-configuration"


@dataclass
class SMARTConfig:
    name: str
    base_url: str
    fhir_url: str
    token_url: str
    client_id: str
    client_secret: str
    auth_url: str
    scopes: list[str]


@dataclass
class OAuthState:
    state_id: str
    extra_state: dict[str]
    code: str | None = None


def generate_state(next_url=None) -> OAuthState:
    state_id = secrets.token_urlsafe(16)
    state = {
        "next_url": next_url,
        "httponly": True,
        "max_age": 600,
    }
    return OAuthState(state_id, state)


def token_for_code(code: str):
    config = SMARTConfig(**session.get("smart_config"))
    data = dict(
        client_id=config.client_id,
        client_secret=config.client_secret,
        grant_type="authorization_code",
        code=code,
        redirect_uri=config.base_url + "oauth_callback",
    )
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_reply = requests.post(config.token_url, data=data, headers=headers)
    return token_reply.json()["access_token"]


def get_smart_config():
    fhir_url = request.args.get("iss")
    app_config = requests.get(f"{fhir_url}/{smart_broadcast}").json()
    smart_config = SMARTConfig(
        name="FHIR demo",
        base_url=request.base_url,
        fhir_url=fhir_url,
        auth_url=app_config["authorization_endpoint"],
        client_id="id",
        client_secret="secret",
        token_url=app_config["token_endpoint"],
        scopes=app_config["scopes_supported"],
    )
    return smart_config


def authenticated(f):
    """Decorator for authenticating with the Hub via OAuth"""

    @wraps(f)
    def decorated(*args, **kwargs):
        if token := session.get("token"):
            return f(token)

        else:
            # redirect to login url on failed auth
            session["smart_config"] = get_smart_config()
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
        "client_secret": config.client_secret,
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
    url = f"{SMARTConfig(**session['smart_config']).fhir_url}/Condition"  # Endpoint with data
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
