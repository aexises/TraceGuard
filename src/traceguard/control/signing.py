"""Purpose-separated Ed25519 signing; verifiers receive only public keys."""

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class Signer:
    def __init__(self, secret: bytes, purpose: str) -> None:
        if len(secret) < 32:
            raise ValueError("signing seed must contain at least 32 bytes")
        seed = hashlib.sha256(purpose.encode() + b"\x00" + secret).digest()
        self._private = Ed25519PrivateKey.from_private_bytes(seed)

    @property
    def public_key(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, value: Any) -> str:
        return base64.b64encode(self._private.sign(canonical(value))).decode("ascii")


def verify(public_key: bytes, value: Any, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(signature, validate=True), canonical(value)
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
