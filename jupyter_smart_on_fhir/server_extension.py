import json
import os
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

import tornado
from jupyter_core.paths import jupyter_runtime_dir
from jupyter_server.base.handlers import JupyterHandler
from jupyter_server.extension.application import ExtensionApp
from jupyter_server.utils import url_path_join
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from tornado.httputil import url_concat
from traitlets import Callable, List, Unicode

from jupyter_smart_on_fhir.auth import SMARTConfig, generate_state

smart_path = "smart-on-fhir"
launch_path = f"{smart_path}/launch"
login_path = f"{smart_path}/login"
callback_path = f"{smart_path}/callback"


def _jupyter_server_extension_points():
    return [
        {"module": "jupyter_smart_on_fhir.server_extension", "app": SMARTExtensionApp}
    ]


class SMARTExtensionApp(ExtensionApp):
    """Jupyter server extension for SMART on FHIR"""

    name = "smart-on-fhir"
    scopes = List(
        Unicode(),
        help="""Scopes to request authorization for at the FHIR endpoint""",
        default_value=["openid", "profile", "fhirUser", "launch", "patient/*.*"],
    ).tag(config=True)

    client_id = Unicode(
        help="""Client ID for the SMART application""",
    ).tag(config=True)

    redirect_uri = Unicode(
        help="""Redirect URI for the SMART application

        If unspecified, will deduce from the current request
        """,
    ).tag(config=True)

    default_issuer = Unicode(
        help="""default issuer for launch page, if none specified
        """,
    ).tag(config=True)

    token_file = Unicode(
        os.path.join(jupyter_runtime_dir(), "smart_token.json"),
        help="""JSON file in which to store tokens""",
    ).tag(config=True)

    smart_launch_hook = Callable(
        None,
        allow_none=True,
        help="""
        Callback for smart launch
        
        Called during the initial launch handler
        Can take action on the provider-specific launch parameter
        
        Hook takes::
        
            smart_launch_hook(launch, url, smart_config, handler)
        
        where
        - launch: the opaque launch parameter in the URL query
        - url: the full URL
        - smart_config: SMARTConfig dataclass
        - handler: the current RequestHandler
        """,
    ).tag(config=True)

    smart_callback_hook = Callable(
        None,
        allow_none=True,
        help="""
        Callback for smart oauthc allback
        
        Called during the initial launch handler
        Can take action on the provider-specific launch parameter
        
        Hook takes::
        
            smart_launch_hook(token, launch, smart_config, handler)
        
        where
        - launch: the opaque launch parameter in the URL query
        - url: the full URL
        - smart_config: SMARTConfig dataclass
        - handler: the current RequestHandler
        """,
    ).tag(config=True)

    def initialize_settings(self):
        os.environ["SMART_TOKEN_FILE"] = self.token_file
        self.settings["smart_auth"] = self
        self.settings["smart_client_id"] = self.client_id
        self.settings["smart_redirect_uri"] = self.redirect_uri
        self.settings["smart_default_issuer"] = self.default_issuer
        self.settings["smart_oauth_state"] = None

    def initialize_handlers(self):
        self.handlers.extend(
            [
                (launch_path, SMARTLaunchHandler),
                (login_path, SMARTLoginHandler),
                (callback_path, SMARTCallbackHandler),
            ]
        )


def get_next_url(handler):
    """Get next url and validate it"""
    next_url = handler.get_argument("next", None)
    if next_url:
        next_url = next_url.replace("\\", "/")
        # make it an absolute path, strip host info
        next_url = "/" + urlparse(next_url).path.strip("/")
        # and relative to self.base_url
        if not (next_url + "/").startswith(handler.base_url):
            next_url = url_path_join(handler.base_url, next_url)
    else:
        next_url = handler.base_url
    return next_url


class SMARTLaunchHandler(JupyterHandler):
    """Handler for SMART on FHIR authentication"""

    @tornado.web.authenticated
    async def get(self):
        smart_auth = self.settings["smart_auth"]
        fhir_url = self.get_argument("iss", self.settings["smart_default_issuer"])
        if not fhir_url:
            raise web.HTTPError(400, "issuer (?iss=...) required")
        smart_config = SMARTConfig.from_url(fhir_url, self.request.full_url())
        self.settings["smart_config"] = smart_config
        self.log.info("Starting smart launch for %s", self.request.query_arguments)
        launch = self.get_argument("launch", "")
        login_params = {
            "launch": launch,
            "scope": " ".join(smart_auth.scopes),
        }
        if self.get_argument("next", None):
            login_params["next"] = get_next_url(self)

        hook = smart_auth.smart_launch_hook
        if hook:
            hook_out = await hook(
                launch=launch,
                url=self.request.full_url(),
                smart_config=smart_config,
                handler=self,
            )
            if hook_out:
                if "scope" in hook_out:
                    login_params["scope"] = hook_out["scope"]
                if "next" in hook_out:
                    login_params["next"] = hook_out["next"]

        # TODO: persist next_url differently
        self.redirect(
            url_concat(url_path_join(self.base_url, login_path), login_params)
        )


class SMARTLoginHandler(JupyterHandler):
    """Login handler for SMART on FHIR"""

    @tornado.web.authenticated
    def get(self):
        state = generate_state(get_next_url(self))
        # only allow a single oauth state to be valid at a time
        if self.settings.get("smart_oauth_state"):
            self.log.warning("Overwriting stale smart oauth state")
        self.settings["smart_oauth_state"] = state
        if state["next_url"]:
            self.log.info("Will redirect to %s after SMART login", state["next_url"])

        smart_config = self.settings["smart_config"]
        auth_url = smart_config.auth_url
        oauth_params = {
            "aud": smart_config.fhir_url,
            "state": state["state_id"],
            "launch": self.get_argument("launch"),
            "redirect_uri": self.settings["smart_redirect_uri"]
            or urljoin(
                self.request.full_url(), url_path_join(self.base_url, callback_path)
            ),
            "client_id": self.settings["smart_client_id"],
            "code_challenge": state["code_challenge"],
            "code_challenge_method": "S256",
            "response_type": "code",
            "scope": self.get_argument("scope"),
        }
        self.redirect(url_concat(auth_url, oauth_params))


class SMARTCallbackHandler(JupyterHandler):
    """Callback handler for SMART on FHIR"""

    async def token_for_code(self, code: str, code_verifier: str) -> dict:
        data = dict(
            client_id=self.settings["smart_client_id"],
            grant_type="authorization_code",
            code=code,
            code_verifier=code_verifier,
            redirect_uri=self.settings["smart_redirect_uri"]
            or urljoin(
                self.request.full_url(), url_path_join(self.base_url, callback_path)
            ),
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            token_reply = await AsyncHTTPClient().fetch(
                self.settings["smart_config"].token_url,
                body=urlencode(data),
                headers=headers,
                method="POST",
            )
        except HTTPClientError as e:
            self.log.error(
                "Error fetching token: %s", e.response.body.decode("utf8", "replace")
            )
            raise
        return json.loads(token_reply.body.decode("utf8", "replace"))

    @tornado.web.authenticated
    async def get(self):
        if "error" in self.request.arguments:
            raise tornado.web.HTTPError(400, self.get_argument("error"))
        code = self.get_argument("code")
        if not code:
            raise tornado.web.HTTPError(
                400, "Error: no code in response from FHIR server"
            )
        state = self.settings.get("smart_oauth_state")
        if not state:
            raise tornado.web.HTTPError(400, "Error: missing persisted oauth state")
        state_id = state["state_id"]
        arg_state = self.get_argument("state")
        if not arg_state:
            raise tornado.web.HTTPError(400, "Error: missing state query argument")
        if arg_state != state_id:
            raise tornado.web.HTTPError(
                400, "Error: state received from FHIR server does not match"
            )
        self.settings["smart_oauth_state"] = None

        token_response = await self.token_for_code(
            code, code_verifier=state["code_verifier"]
        )
        smart_auth = self.settings["smart_auth"]
        self.log.info(
            "Persisting token info to %s and $SMART_TOKEN", smart_auth.token_file
        )
        with Path(smart_auth.token_file).open("w") as f:
            json.dump(
                {
                    "token": token_response,
                    "fhir_url": self.settings["smart_config"].fhir_url,
                    # the full output of the .well-known/smart-configuration endpoint
                    "smart_config": self.settings["smart_config"].smart_config,
                },
                f,
                sort_keys=True,
                indent=1,
            )
        os.environ["SMART_TOKEN"] = token_response["access_token"]

        redirected = False
        hook = self.settings["smart_auth"].smart_callback_hook
        if hook:
            # hook is responsible for redirect (?)
            redirected = await hook(
                token_response=token_response,
                smart_config=self.settings["smart_config"],
                handler=self,
            )
        if not redirected:
            self.redirect(state["next_url"] or self.base_url)


if __name__ == "__main__":
    SMARTExtensionApp.launch_instance()
