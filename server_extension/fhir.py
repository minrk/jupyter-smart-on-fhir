from jupyter_server.serverapp import ServerApp
from jupyter_server.base.handlers import JupyterHandler
import tornado
import json
import requests
import secrets
from urllib.parse import urlencode, urljoin
import hashlib
import base64
from authlib.jose import jwk
import time
import jwt

smart_path = "/extension/smart"
login_path = "/extension/smart/login"
callback_path = "/extension/smart/oauth_callback"

key_file = "jwtRS256.key"
key_id = "somekey"


def _jupyter_server_extension_points():
    return [{"module": "fhir"}]


def _load_jupyter_server_extension(serverapp: ServerApp):
    handlers = [
        (smart_path, SmartAuthHandler),
        (login_path, SmartLoginHandler),
        (callback_path, SmartCallbackHandler),
    ]
    # First generate a RSA key pair and extract the public key
    # openssl genrsa -out jwtRS256.key 2048
    # openssl rsa -in jwtRS256.key -pubout -out jwtRS256.key.pub
    # Load the RSA public key
    with open(key_file + ".pub", "rb") as f:
        pem_public_key = f.read()

    # Create JWKS and store in SMART-compliant format
    jwks = jwk.dumps(pem_public_key, kty="RSA")
    jwks["kid"] = key_id
    jwks["alg"] = "RS256"
    jwks_compliant = {"keys": [jwks]}
    print(json.dumps(jwks_compliant, indent=2))

    serverapp.web_app.add_handlers(".*$", handlers)


def fetch_smart_config(url: str) -> dict:
    """Fetch the smart configuration broadcasted for each FHIR endpoint"""
    broadcast = ".well-known/smart-configuration"
    config = requests.get(f"{url}/{broadcast}")
    return config.json()


def generate_state(next_url=None) -> dict:
    state_id = secrets.token_urlsafe(16)
    state = {
        "id": state_id,
        "next_url": next_url,
        "path": "./cookie",
        "httponly": True,
        "max_age": 600,
    }
    return state


class SmartAuthHandler(JupyterHandler):
    @tornado.web.authenticated
    def get(self):
        fhir_url = self.get_argument("iss")
        smart_config = fetch_smart_config(fhir_url)
        self.settings["launch"] = self.get_argument("launch")
        self.settings["fhir_endpoint"] = fhir_url
        self.settings["smart_config"] = smart_config
        token = self.settings.get("smart_token")
        if not token:
            self.settings["next_url"] = self.request.uri
            self.redirect(login_path)
        else:
            data = self.get_data(token)
            self.write(f"Authorization success: Fetched {str(data)}")
            self.finish()

    def get_data(self, token: str):
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/fhir+json",
            "User-Agent": "Jupyter",
        }
        url = f"{self.settings['fhir_endpoint']}/Condition"  # Endpoint with data
        f = requests.get(url, headers=headers)
        try:
            return f.json()
        except requests.exceptions.JSONDecodeError:
            print(f.text)
            raise RuntimeError(f.text)


class SmartLoginHandler(JupyterHandler):
    @tornado.web.authenticated
    def get(self):
        # Check if referred to from endpoint, otherwise be angry and give up
        state = generate_state()
        self.set_cookie("state_id", state["id"])  # does this need to be secure?
        scopes = [
            "openid",
            "profile",
            "fhirUser",
            "launch",
            "patient/*.*",
        ]
        auth_url = self.settings["smart_config"]["authorization_endpoint"]
        self.settings["code_verifier"] = code_verifier = secrets.token_urlsafe(53)
        code_challenge_b = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge_b).rstrip(b"=")
        headers = {
            "aud": self.settings["fhir_endpoint"],
            "state": state["id"],
            "launch": self.settings["launch"],
            "redirect_uri": urljoin(self.request.full_url(), callback_path),
            "client_id": "marvin",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "scope": " ".join(scopes),
        }
        self.redirect(f"{auth_url}?{urlencode(headers)}")


class SmartCallbackHandler(JupyterHandler):
    def generate_jwt(self):
        jwt_dict = {
            "iss": "marvin",
            "sub": "marvin",
            "aud": self.settings["smart_config"]["token_endpoint"],
            "jti": "someid",
            "exp": int(time.time() + 3600),
        }
        headers = {"kid": key_id}
        with open(key_file, "rb") as f:
            private_key = f.read()
        return jwt.encode(jwt_dict, private_key, "RS256", headers)

    def token_for_code(self, code: str):
        data = dict(
            client_id="marvin",
            grant_type="authorization_code",
            code=code,
            code_verifier=self.settings["code_verifier"],
            redirect_uri=urljoin(self.request.full_url(), callback_path),
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=self.generate_jwt(),
        )
        # print(data['client_assertion'])
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_reply = requests.post(
            self.settings["smart_config"]["token_endpoint"], data=data, headers=headers
        )
        print(token_reply.json())
        return token_reply.json()["access_token"]

    @tornado.web.authenticated
    def get(self):
        if "error" in self.request.arguments:
            print(f"Error: {self.get_argument('error')}")
        code = self.get_argument("code")
        if not code:
            print("Error: no code")
        if self.get_argument("state") != self.get_cookie("state_id"):
            print("Error: state does not match")
        self.settings["smart_token"] = self.token_for_code(code)
        self.redirect(self.settings["next_url"])
