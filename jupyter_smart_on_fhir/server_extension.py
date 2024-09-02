from jupyter_server.extension.application import ExtensionApp
from jupyter_server.serverapp import ServerApp
from jupyter_server.base.handlers import JupyterHandler
import tornado
import requests
import secrets
from urllib.parse import urlencode, urljoin
import hashlib
import base64
from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state

smart_path = "/smart"
login_path = "/smart/login"
callback_path = "/smart/oauth_callback"


def _jupyter_server_extension_points():
    return [
        {"module": "jupyter_smart_on_fhir.server_extension", "app": SmartExtensionApp}
    ]


class SmartExtensionApp(ExtensionApp):
    name = "fhir"
    default_url = "/smart"
    load_other_extensions = True
    file_url_prefix = "/fhir"

    def initialize_handlers(self):
        self.handlers.extend(
            [
                (smart_path, SmartAuthHandler),
                (login_path, SmartLoginHandler),
                (callback_path, SmartCallbackHandler),
            ]
        )


class SmartAuthHandler(JupyterHandler):
    @tornado.web.authenticated
    def get(self):
        fhir_url = self.get_argument("iss")
        smart_config = SMARTConfig.from_url(fhir_url, self.request.full_url())
        self.settings["launch"] = self.get_argument("launch")
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
        url = (
            f"{self.settings['smart_config'].fhir_url}/Condition"  # Endpoint with data
        )
        f = requests.get(url, headers=headers)
        try:
            return f.json()
        except requests.exceptions.JSONDecodeError:
            print(f.text)
            raise RuntimeError(f.text)


class SmartLoginHandler(JupyterHandler):
    @tornado.web.authenticated
    def get(self):
        state = generate_state()
        self.set_secure_cookie("state_id", state["id"])
        scopes = [
            "openid",
            "profile",
            "fhirUser",
            "launch",
            "patient/*.*",
        ]
        smart_config = self.settings["smart_config"]
        auth_url = smart_config.auth_url
        code_verifier = secrets.token_urlsafe(53)
        self.set_secure_cookie("code_verifier", code_verifier)
        code_challenge_b = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge_b).rstrip(b"=")
        headers = {
            "aud": smart_config.fhir_url,
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
            self.settings["smart_config"].token_url, data=data, headers=headers
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


if __name__ == "__main__":
    SmartExtensionApp.launch_instance()
