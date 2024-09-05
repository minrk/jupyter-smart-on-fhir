import requests

from oauthenticator.generic import GenericOAuthenticator

c = get_config()  # noqa

# Base url for a simulated FHIR application, by running docker compose setup from https://github.com/smart-on-fhir/smart-launcher-v2/
# Configuration in the sandbox:
# - Launch Type: Provider Standalone Launch
# - FHIR Version: R4 (most modern)
# The URL below is the server's FHIR base URL, useful for authentication.
fhir_base_url = "http://localhost:8080/v/r4/sim/WzIsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCIiLCIiLCIiLDEsMV0/fhir"
# Location where a SMART on FHIR application broadcasts configuration
smart_config_location = ".well-known/smart-configuration"
client_id = "id"
client_secret = "secret"
id_scopes = [
    "openid",
    "fhirUser",
]


# Generic OAuthenticator
c.JupyterHub.authenticator_class = GenericOAuthenticator
c.GenericOAuthenticator.oauth_callback_url = "http://localhost:8000/hub/oauth_callback"
c.GenericOAuthenticator.client_id = client_id
c.GenericOAuthenticator.client_secret = client_secret
c.GenericOAuthenticator.scope = id_scopes
c.GenericOAuthenticator.allow_all = True
c.Application.log_level = "DEBUG"
# SMART requires an extra parameter 'aud' which corresponds with the FHIR application URL
c.GenericOAuthenticator.extra_authorize_params = {"aud": fhir_base_url}

# Fetch the config
smart_config = requests.get(f"{fhir_base_url}/{smart_config_location}").json()
c.GenericOAuthenticator.authorize_url = smart_config["authorization_endpoint"]
c.GenericOAuthenticator.token_url = smart_config["token_endpoint"]
for scope in c.GenericOAuthenticator.scope:
    if scope not in smart_config["scopes_supported"]:
        raise AttributeError("Scope {scope} not supported through SMART application")
# With the supplied scopes, auth code also grants an ID token
c.GenericOAuthenticator.userdata_from_id_token = True
# Only one field to derive a name from, and it contains (at least) slashes
c.GenericOAuthenticator.username_claim = lambda r: r["fhirUser"].replace("/", "_")

# Below we set up a service that fetches data from the FHIR server
# using the same server we used for authentication above
data_scopes = [
    "launch",
    "profile",
    "patient/*.*",
]
scopes_for_service = " ".join(id_scopes + data_scopes)
c.JupyterHub.services = [
    {
        "name": "fhir",
        "url": "http://127.0.0.1:10101",
        "command": ["flask", "run", "--port=10101"],
        "environment": {
            "FLASK_APP": "jupyter_smart_on_fhir/hub_service.py",
            "SCOPES": scopes_for_service,
            "CLIENT_ID": client_id,
            "SSH_KEY_PATH": "jwtRS256.key",
            "SSH_KEY_ID": "1",
        },
    },
]
c.JupyterHub.load_roles = [
    {
        "name": "user",
        "scopes": [
            "access:services!service=fhir",  # access this service
            "self",  # and all of the standard things for a user
        ],
    }
]

# dummy auth and simple spawner for testing
# any username and password will work
c.JupyterHub.spawner_class = "simple"

# listen only on localhost while testing with wide-open auth
c.JupyterHub.ip = "127.0.0.1"
