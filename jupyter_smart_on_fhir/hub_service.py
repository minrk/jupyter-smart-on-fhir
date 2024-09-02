#!/usr/bin/env python3
"""
SMART service authentication for a FHIR endpoint with the Hub
- Asymmetric authentication
"""

import os
import time
import secrets
from functools import wraps
from flask import Flask, Response, make_response, redirect, request, session
from jupyterhub.services.auth import HubOAuth
import requests
from urllib.parse import urlencode
import jwt
from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state, load_keys

prefix = os.environ.get("JUPYTERHUB_SERVICE_PREFIX", "/")
auth = HubOAuth(api_token=os.environ["JUPYTERHUB_API_TOKEN"], cache_max_age=60)
app = Flask(__name__)
# encryption key for session cookies
app.secret_key = secrets.token_bytes(32)


def generate_jwt() -> str:
    """Generate a JWT for the SMART asymmetric client authentication"""
    config = SMARTConfig(**session.get("smart_config"))
    jwt_dict = {
        "iss": session["client_id"],
        "sub": "client",
        "aud": config.token_url,
        "jti": "jwt_id",
        "exp": int(time.time() + 3600),
    }
    ((key_id, private_key),) = session["keys"].items()
    headers = {"kid": key_id}
    return jwt.encode(jwt_dict, private_key, "RS256", headers)


def token_for_code(code: str):
    config = SMARTConfig(**session.get("smart_config"))
    data = dict(
        client_id=session["client_id"],
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
        if token := request.cookies.get("smart_token"):
            return f(token, *args, **kwargs)

        else:
            session["client_id"] = os.environ["CLIENT_ID"]
            session["keys"] = load_keys()
            session["smart_config"] = SMARTConfig.from_url(
                request.args.get("iss"), request.base_url
            )
            state = generate_state(next_url=request.path)
            from_redirect = make_response(start_oauth_flow(state_id=state["id"]))
            from_redirect.set_cookie(
                "state_id", state["id"], secure=True, httponly=True
            )
            from_redirect.set_cookie("next_url", state["next_url"])
            return from_redirect

    return decorated


def start_oauth_flow(state_id: str, scopes: list[str] | None = None):
    config = session.get("smart_config")
    redirect_uri = config.base_url + "oauth_callback"
    config.scopes = os.environ.get("SCOPES", "").split()
    scopes = scopes or config.scopes
    headers = {
        "aud": config.fhir_url,
        "state": state_id,
        "redirect_uri": redirect_uri,
        "launch": request.args.get("launch"),
        "client_id": session["client_id"],
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
    to_next_url = make_response(redirect(next_url))
    to_next_url.set_cookie("smart_token", token, secure=True, httponly=True)
    return to_next_url
