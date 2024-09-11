from dataclasses import dataclass, asdict
import requests
import secrets
import jwt
import json
import os
from pathlib import Path


@dataclass
class SMARTConfig:
    """Client-side session-scoped configuration to connect to a FHIR endpoint with SMART authorization"""

    base_url: str
    fhir_url: str
    token_url: str
    auth_url: str
    scopes: list[str]
    broadcast_path: str = ".well-known/smart-configuration"

    @classmethod
    def from_url(cls, iss: str, base_url: str, **kwargs) -> "SMARTConfig":
        app_config = requests.get(f"{iss}/{cls.broadcast_path}").json()
        scopes = kwargs.pop("scopes", [])
        return cls(
            base_url=base_url,
            fhir_url=iss,
            token_url=app_config["token_endpoint"],
            auth_url=app_config["authorization_endpoint"],
            scopes=scopes,
        )

    def to_dict(self):
        return asdict(self)


def generate_state(next_url=None) -> dict:
    """Generate a state cookie for OAuth flow"""
    return {
        "state_id": secrets.token_urlsafe(16),
        "next_url": next_url,
        "httponly": True,
        "max_age": 600,
    }


def get_jwks_from_key(key_file: Path, key_id: str = "1") -> str:
    """Generate a JWKS from a public key file. Not required for end users, but useful for development"""
    try:
        with open(key_file + ".pub", "r") as f:
            public_key = f.read()
    except FileNotFoundError as e:
        raise FileNotFoundError(
            f"Public key file {key_file}.pub not found. Please generate a new key pair with e.g.\n"
            f"ssh-keygen -t rsa -b 4096 -m PEM -f {key_file} -q -N"
        ) from e

    alg = jwt.get_algorithm_by_name("RS256")
    key = alg.prepare_key(public_key)
    jwk = alg.to_jwk(key, as_dict=True)
    jwk.update({"alg": "RS256", "kid": key_id})
    jwks_smart = {"keys": [jwk]}
    jwks_smart_str = json.dumps(jwks_smart)
    return jwks_smart_str


def validate_keys() -> dict[str, bytes]:
    """Load the private key from environment variables"""
    key_path = Path(os.environ.get("SSH_KEY_PATH", "~/.ssh/id_rsa"))
    key_id = os.environ.get("SSH_KEY_ID", "1")
    try:
        with open(key_path, "rb") as f:
            private_key = f.read()
        jwt.encode({"iss": "test"}, private_key, "RS256")
    except FileNotFoundError as e:
        raise FileNotFoundError(
            f"Private key file {key_path} not found. Please generate a new key pair with e.g.\n"
            f"ssh-keygen -t rsa -b 4096 -m PEM -f {key_path} -q -N"
        ) from e
    except jwt.exceptions.InvalidKeyError as e:
        raise jwt.exceptions.InvalidKeyError(
            f"Private key file {key_path} is not a valid RSA key. Please generate a new key pair with e.g.\n"
            f"ssh-keygen -t rsa -b 4096 -m PEM -f {key_path} -q -N"
        ) from e
    return {key_id: str(key_path.absolute())}
