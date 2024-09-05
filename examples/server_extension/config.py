# Configuration file for jupyter-server.

c = get_config()  # noqa

# Enable the SMART server extension
c.ServerApp.jpserver_extensions = {"jupyter_smart_on_fhir.server_extension": True}
c.ServerApp.ip = "0.0.0.0"
c.ServerApp.allow_root = True

# Configure the SmartExtensionApp
c.SMARTExtensionApp.scopes = [
    "openid",
    "profile",
    "fhirUser",
    "launch",
    "patient/*.*",
]
c.SMARTExtensionApp.client_id = "client_id"
