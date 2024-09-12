#!/usr/bin/env python3
"""
SMART service authentication for a FHIR endpoint with the Hub
- Asymmetric authentication
"""

import os
import time
import secrets
from functools import wraps
from flask import (
    Flask,
    Response,
    make_response,
    redirect,
    request,
    session,
    current_app,
)
import requests
from urllib.parse import urlencode
import jwt
import base64
from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state, validate_keys
from cryptography.fernet import Fernet, InvalidToken

prefix = os.environ.get("JUPYTERHUB_SERVICE_PREFIX", "/")


def create_app():
    """Create the Flask app with configuration"""
    app = Flask(__name__)
    # encryption key for session cookies
    secret_key = secrets.token_bytes(32)
    app.secret_key = secret_key
    app.config["fernet"] = Fernet(base64.urlsafe_b64encode(secret_key))
    # settings passed from the Hub
    app.config["client_id"] = os.environ["CLIENT_ID"]
    app.config["keys"] = validate_keys()

    @app.route(prefix)
    @authenticated
    def fetch_data(token: str) -> Response:
        """Fetch data from a FHIR endpoint"""
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/fhir+json",
            "User-Agent": "JupyterHub",
        }
        url = f"{session['smart_config']['fhir_url']}/Condition"  # Endpoint with data
        f = requests.get(url, headers=headers)
        return Response(f.text, mimetype="application/json")

    @app.route(prefix + "oauth_callback")
    def callback() -> Response:
        """Callback endpoint to finish OAuth flow"""
        state_id = get_encrypted_cookie("state_id")
        if not state_id:
            return Response("No local state ID cookie found", status=400)
        next_url = get_encrypted_cookie("next_url") or "/"

        if error := request.args.get("error", False):
            return Response(
                f"Error in OAuth: {request.args.get('error_description', error)}",
                status=400,
            )
        code = request.args.get("code")
        if not code:
            return Response(
                "OAuth callback did not return authorization code", status=400
            )
        arg_state = request.args.get("state", None)
        if arg_state != state_id:
            return Response(
                "OAuth state does not match. Try logging in again.", status=403
            )
        token = token_for_code(code)
        set_encrypted_cookie("smart_token", token)
        return make_response(redirect(next_url))

    return app


def get_encrypted_cookie(key: str) -> str | None:
    """Fetch and decrypt an encrypted cookie"""
    cookie = session.get(key)
    if cookie:
        try:
            return current_app.config["fernet"].decrypt(cookie).decode("ascii")
        except InvalidToken:
            pass  # maybe warn
    return None


def set_encrypted_cookie(key: str, value: str):
    """Store an encrypted cookie"""
    session[key] = current_app.config["fernet"].encrypt(value.encode("ascii"))


def generate_jwt() -> str:
    """Generate a JWT for the SMART asymmetric client authentication"""
    jwt_dict = {
        "iss": current_app.config["client_id"],
        "sub": current_app.config["client_id"],
        "aud": session["smart_config"]["token_url"],
        "jti": "jwt_id",
        "exp": int(time.time() + 3600),
    }
    ((key_id, private_key_path),) = current_app.config["keys"].items()
    with open(private_key_path, "rb") as f:
        private_key = f.read()
    headers = {"kid": key_id}
    return jwt.encode(jwt_dict, private_key, "RS256", headers)


def token_for_code(code: str) -> str:
    """Exchange an authorization code for an access token"""
    data = dict(
        client_id=current_app.config["client_id"],
        grant_type="authorization_code",
        code=code,
        redirect_uri=session["smart_config"]["base_url"] + "oauth_callback",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion=generate_jwt(),
    )
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_reply = requests.post(
        session["smart_config"]["token_url"], data=data, headers=headers
    )
    try:
        return token_reply.json()["access_token"]
    except KeyError:
        raise ValueError(
            f"No access token in token reply: received error messsage {token_reply.get('error_description')}"
        )


def authenticated(f):
    """Decorator for authenticating with the Hub via OAuth"""

    @wraps(f)
    def decorated(*args, **kwargs):
        if "iss" not in request.args:
            return Response(
                "GET request misses 'iss' argument. Was service launched from EHR?",
                status=400,
            )

        if token := get_encrypted_cookie("smart_token"):
            return f(token, *args, **kwargs)
        else:
            session["smart_config"] = SMARTConfig.from_url(
                request.args["iss"],
                request.base_url,
                scopes=os.environ.get("SCOPES", "").split(),
            ).to_dict()
            state = generate_state(next_url=request.path)
            for key in ("next_url", "state_id"):
                set_encrypted_cookie(key, state[key])
            return make_response(start_oauth_flow(state_id=state["state_id"]))

    return decorated


def start_oauth_flow(state_id: str, scopes: list[str] | None = None) -> Response:
    """Start the OAuth flow by redirecting to the authorization endpoint"""
    config = SMARTConfig(**session.get("smart_config"))
    redirect_uri = config.base_url + "oauth_callback"
    scopes = scopes or config.scopes
    headers = {
        "aud": config.fhir_url,
        "state": state_id,
        "redirect_uri": redirect_uri,
        "launch": request.args["launch"],
        "client_id": current_app.config["client_id"],
        "response_type": "code",
        "scopes": " ".join(scopes),
    }
    auth_url = f"{config.auth_url}?{urlencode(headers)}"
    return redirect(auth_url)
