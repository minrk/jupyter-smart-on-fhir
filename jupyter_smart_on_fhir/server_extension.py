import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode, urljoin

import tornado
from jupyter_server.base.handlers import JupyterHandler
from jupyter_server.extension.application import ExtensionApp
from jupyter_server.utils import url_path_join
from tornado.httpclient import AsyncHTTPClient
from traitlets import List, Unicode

from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state

smart_path = "/smart"
login_path = "/smart/login"
callback_path = "/smart/oauth_callback"


def _jupyter_server_extension_points():
    return [
        {"module": "jupyter_smart_on_fhir.server_extension", "app": SMARTExtensionApp}
    ]


class SMARTExtensionApp(ExtensionApp):
    """Jupyter server extension for SMART on FHIR"""

    name = "fhir"
    scopes = List(
        Unicode(),
        help="""Scopes to request authorization for at the FHIR endpoint""",
        default_value=["openid", "profile", "fhirUser", "launch", "patient/*.*"],
    ).tag(config=True)

    client_id = Unicode(
        help="""Client ID for the SMART application""", default_value="test_id"
    ).tag(config=True)

    def initialize_settings(self):
        self.settings["scopes"] = self.scopes
        self.settings["client_id"] = self.client_id

    def initialize_handlers(self):
        self.handlers.extend(
            [
                (smart_path, SMARTAuthHandler),
                (login_path, SMARTLoginHandler),
                (callback_path, SMARTCallbackHandler),
            ]
        )


class SMARTAuthHandler(JupyterHandler):
    """Handler for SMART on FHIR authentication"""

    @tornado.web.authenticated
    async def get(self):
        fhir_url = self.get_argument("iss")
        smart_config = SMARTConfig.from_url(fhir_url, self.request.full_url())
        self.settings["launch"] = self.get_argument("launch")
        self.settings["smart_config"] = smart_config
        token = self.settings.get("smart_token")
        if not token:
            # TODO: persist next_url differently
            self.settings["next_url"] = self.request.uri
            self.redirect(login_path)
        else:
            data = await self.get_data(token)
            self.write(f"Authorization success: Fetched {str(data)}")
            self.finish()

    async def get_data(self, token: str) -> dict:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/fhir+json",
            "User-Agent": "Jupyter",
        }
        url = (
            f"{self.settings['smart_config'].fhir_url}/Condition"  # Endpoint with data
        )
        resp = await AsyncHTTPClient().fetch(url, headers=headers)
        return json.loads(resp.body.decode("utf8", "replace"))


class SMARTLoginHandler(JupyterHandler):
    """Login handler for SMART on FHIR"""

    @tornado.web.authenticated
    def get(self):
        state = generate_state()
        self.set_secure_cookie("state_id", state["state_id"])
        if state["next_url"]:
            self.set_secure_cookie("next_url", state["next_url"])

        scopes = self.settings["scopes"]
        smart_config = self.settings["smart_config"]
        auth_url = smart_config.auth_url
        code_verifier = secrets.token_urlsafe(53)
        self.set_secure_cookie("code_verifier", code_verifier)
        code_challenge_b = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge_b).rstrip(b"=")
        headers = {
            "aud": smart_config.fhir_url,
            "state": state["state_id"],
            "launch": self.settings["launch"],
            "redirect_uri": urljoin(
                self.request.full_url(), url_path_join(self.base_url, callback_path)
            ),
            "client_id": self.settings["client_id"],
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "scope": " ".join(scopes),
        }
        self.redirect(f"{auth_url}?{urlencode(headers)}")


class SMARTCallbackHandler(JupyterHandler):
    """Callback handler for SMART on FHIR"""

    async def token_for_code(self, code: str) -> str:
        data = dict(
            client_id=self.settings["client_id"],
            grant_type="authorization_code",
            code=code,
            code_verifier=self.get_signed_cookie("code_verifier").decode("ascii"),
            redirect_uri=urljoin(
                self.request.full_url(), url_path_join(self.base_url, callback_path)
            ),
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_reply = await AsyncHTTPClient().fetch(
            self.settings["smart_config"].token_url,
            body=urlencode(data),
            headers=headers,
            method="POST",
        )
        return json.loads(token_reply.body.decode("utf8", "replace"))["access_token"]

    @tornado.web.authenticated
    async def get(self):
        if "error" in self.request.arguments:
            raise tornado.web.HTTPError(400, self.get_argument("error"))
        code = self.get_argument("code")
        if not code:
            raise tornado.web.HTTPError(
                400, "Error: no code in response from FHIR server"
            )
        state_id = self.get_signed_cookie("state_id")
        if state_id is None:
            raise tornado.web.HTTPError(400, "Error: missing state cookie")
        state_id = state_id.decode("utf-8")
        arg_state = self.get_argument("state")
        if not arg_state:
            raise tornado.web.HTTPError(400, "Error: missing state argument")
        if arg_state != state_id:
            raise tornado.web.HTTPError(
                400, "Error: state received from FHIR server does not match"
            )
        self.settings["smart_token"] = await self.token_for_code(code)
        # TODO: persist next_url differently
        self.redirect(self.settings["next_url"])


if __name__ == "__main__":
    SMARTExtensionApp.launch_instance()
