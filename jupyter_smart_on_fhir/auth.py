from dataclasses import dataclass
import requests
import secrets

@dataclass
class SMARTConfig:
    base_url: str
    fhir_url: str
    token_url: str
    auth_url: str
    scopes: list[str] # Todo: move to settings
    broadcast_path: str = ".well-known/smart-configuration"

    @classmethod
    def from_url(cls, iss: str, base_url: str):
        app_config = requests.get(f"{iss}/{cls.broadcast_path}").json()
        return cls(
            base_url=base_url,
            fhir_url=iss,
            token_url=app_config["token_endpoint"],
            auth_url=app_config["authorization_endpoint"],
            scopes=app_config["scopes_supported"],
        )


def generate_state(next_url=None) -> dict:
    return {
        "id": secrets.token_urlsafe(16),
        "next_url": next_url,
        "httponly": True,
        "max_age": 600,
    }