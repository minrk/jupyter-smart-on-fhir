from jupyter_server.serverapp import ServerApp
from jupyter_server.base.handlers import JupyterHandler
import tornado
import requests
import secrets
from urllib.parse import urlencode, urljoin
import hashlib
import base64
from common.config import SMARTConfig, generate_state

smart_path = "/extension/smart"
login_path = "/extension/smart/login"
callback_path = "/extension/smart/oauth_callback"


def _jupyter_server_extension_points():
    return [{"module": "fhir"}]


def _load_jupyter_server_extension(serverapp: ServerApp):
    handlers = [
        (smart_path, SmartAuthHandler),
        (login_path, SmartLoginHandler),
        (callback_path, SmartCallbackHandler),
    ]
    serverapp.web_app.add_handlers(".*$", handlers)


class SmartAuthHandler(JupyterHandler):
    @tornado.web.authenticated
    def get(self):
        fhir_url = self.get_argument("iss")
        smart_config = SMARTConfig.from_url(fhir_url, self.request.base_url)
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
        self.set_secure_cookie("state_id", state["id"])  # does this need to be secure?
        scopes = [
            "openid",
            "profile",
            "fhirUser",
            "launch",
            "patient/*.*",
        ]
        auth_url = self.settings["smart_config"]["authorization_endpoint"]
        code_verifier = secrets.token_urlsafe(53)
        self.set_secure_cookie("code_verifier", code_verifier)
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
    def token_for_code(self, code: str):
        data = dict(
            client_id="marvin",
            grant_type="authorization_code",
            code=code,
            code_verifier=self.get_signed_cookie("code_verifier"),
            redirect_uri=urljoin(self.request.full_url(), callback_path),
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_reply = requests.post(
            self.settings["smart_config"]["token_endpoint"], data=data, headers=headers
        )
        return token_reply.json()["access_token"]

    @tornado.web.authenticated
    def get(self):
        if "error" in self.request.arguments:
            print(f"Error: {self.get_argument('error')}")
        code = self.get_argument("code")
        if not code:
            print("Error: no code")
        if self.get_argument("state") != self.get_signed_cookie("state_id"):
            print("Error: state does not match")
        self.settings["smart_token"] = self.token_for_code(code)
        self.redirect(self.settings["next_url"])
