"""Ed25519, X25519, HKDF-SHA256 and AES-256-GCM helpers over the `cryptography` package."""
import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag  # noqa: F401
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def raw_public(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def new_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def sign(key: Ed25519PrivateKey, data: bytes) -> str:
    return b64e(key.sign(data))


def verify(public_b64: str, signature_b64: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64d(public_b64)).verify(b64d(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def signing_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def signing_key_from_bytes(data: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(data)


def new_ephemeral_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def agree(private: X25519PrivateKey, peer_public: bytes) -> bytes:
    return private.exchange(X25519PublicKey.from_public_bytes(peer_public))


def hkdf(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def seal_bytes(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def open_bytes(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
