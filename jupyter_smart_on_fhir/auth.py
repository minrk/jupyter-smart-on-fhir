from dataclasses import dataclass
import requests
import secrets
import jwt
import json


@dataclass
class SMARTConfig:
    base_url: str
    fhir_url: str
    token_url: str
    auth_url: str
    scopes: list[str]
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


def get_jwks_from_key(key_file: str = "jwtRS256.key", key_id: str = "1") -> str:
    try:
        # Todo: move try-except to top level
        with open(key_file + ".pub", "r") as f:
            public_key = f.read()
    except FileNotFoundError:
        print(
            f"Public key file {key_file}.pub not found. Please generate a new key pair with e.g.\n"
            f"ssh-keygen -t rsa -b 4096 -m PEM -f {key_file} -q -N"
        )
        with open(key_file + ".pub", "rb") as f:
            public_key = f.read()

    alg = jwt.get_algorithm_by_name("RS256")
    key = alg.prepare_key(public_key)
    jwk = alg.to_jwk(key, as_dict=True)
    jwk.update({"alg": "RS256", "kid": key_id})
    jwks_smart = {"keys": [jwk]}
    jwks_smart_str = json.dumps(jwks_smart, indent=2)
    return jwks_smart_str
