"""did:web identifiers and verifiable credentials.

The registry is an in-memory map from did:web URLs to documents, and credentials
are signed with Ed25519 over their canonical JSON.
"""
import json
from datetime import datetime, timedelta, timezone

from . import crypto

EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


def iso(t: float) -> str:
    return (EPOCH + timedelta(seconds=t)).isoformat()


class CredentialError(Exception):
    pass


class Registry:
    def __init__(self):
        self._resources = {}

    @staticmethod
    def did_to_url(did: str) -> str:
        """did:web:host:path:segments -> https://host/path/segments/did.json"""
        parts = did.split(":")
        if parts[:2] != ["did", "web"] or len(parts) < 3:
            raise ValueError(f"not a did:web identifier: {did}")
        path = "/".join(parts[3:]) or ".well-known"
        return f"https://{parts[2]}/{path}/did.json"

    def publish(self, url: str, document: dict) -> None:
        self._resources[url] = crypto.canonical(document)

    def fetch(self, url: str) -> dict:
        return json.loads(self._resources[url])

    def resolve(self, did: str) -> dict:
        return self.fetch(self.did_to_url(did))


class Identity:
    """An organization's DID and private key; the key is provisioned into its enclave."""

    def __init__(self, did: str, registry: Registry):
        self.did = did
        self._key = crypto.new_signing_key()
        registry.publish(registry.did_to_url(did), {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": did + "#key-1", "type": "JsonWebKey2020", "controller": did,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519",
                                 "x": crypto.b64e(crypto.raw_public(self._key))}}],
            "assertionMethod": [did + "#key-1"],
        })

    def export_key(self) -> str:
        return crypto.b64e(crypto.signing_key_bytes(self._key))

    def sign(self, data: bytes) -> dict:
        return did_proof(self.did, self._key, data)

    def issue(self, subject_did: str, cred_type: str, claims: dict, valid_from: float,
              valid_until: float) -> dict:
        vc = {"@context": ["https://www.w3.org/ns/credentials/v2"],
              "type": ["VerifiableCredential", cred_type],
              "issuer": self.did, "validFrom": iso(valid_from), "validUntil": iso(valid_until),
              "credentialSubject": {"id": subject_did, **claims}}
        vc["proof"] = {"type": "Ed25519Signature-PoC", **self.sign(crypto.canonical(vc))}
        return vc


def did_proof(did: str, key, data: bytes) -> dict:
    return {"verificationMethod": did + "#key-1", "sig": crypto.sign(key, data)}


def verify_did_signature(registry: Registry, did: str, proof: dict, data: bytes) -> bool:
    try:
        document = registry.resolve(did)
    except (KeyError, ValueError):
        return False
    for method in document.get("verificationMethod", []):
        if method["id"] == proof.get("verificationMethod") and method["controller"] == did:
            return crypto.verify(method["publicKeyJwk"]["x"], proof.get("sig", ""), data)
    return False


def verify_credential(registry: Registry, vc: dict, now: float, issuer: str, cred_type: str) -> dict:
    """Returns the credential subject or raises CredentialError."""
    body = {k: v for k, v in vc.items() if k != "proof"}
    if vc.get("issuer") != issuer or cred_type not in vc.get("type", []):
        raise CredentialError("unexpected issuer or credential type")
    if not verify_did_signature(registry, issuer, vc.get("proof", {}), crypto.canonical(body)):
        raise CredentialError("credential signature invalid")
    if not vc["validFrom"] <= iso(now) <= vc["validUntil"]:
        raise CredentialError("credential expired or not yet valid")
    return vc["credentialSubject"]
