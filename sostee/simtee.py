"""SimTEE: a simulated TEE modelled after Intel SGX with DCAP attestation.

It reproduces the trust relationships and interfaces of a TEE (vendor root,
measurement, quotes, sealing, ecall/ocall boundary). Hardware isolation is
assumed, not enforced.
"""
import functools
import inspect
import json
import os
import sys

from . import crypto


class AttestationError(Exception):
    pass


@functools.lru_cache(maxsize=None)
def measure(app_cls) -> str:
    """SHA-256 over the source of the application and its base classes."""
    seen, parts = set(), []
    for klass in app_cls.__mro__:
        if klass is object or klass.__module__ in seen:
            continue
        seen.add(klass.__module__)
        source = inspect.getsource(sys.modules[klass.__module__])
        parts.append(klass.__module__.encode() + b"\0" + source.encode())
    parts.append(app_cls.__qualname__.encode())
    return crypto.sha256(b"\0".join(parts)).hex()


class Vendor:
    def __init__(self, name: str = "simtee-vendor"):
        self.name = name
        self._root = crypto.new_signing_key()
        self.root_public = crypto.b64e(crypto.raw_public(self._root))

    def provision(self, platform_id: str) -> "Platform":
        attestation_key = crypto.new_signing_key()
        cert = {"issuer": self.name, "platform_id": platform_id,
                "att_pub": crypto.b64e(crypto.raw_public(attestation_key))}
        cert["sig"] = crypto.sign(self._root, crypto.canonical(cert))
        return Platform(platform_id, attestation_key, cert)


def verify_evidence(evidence: dict, vendor_root_public: str) -> dict:
    """Checks the vendor -> platform chain and the quote; returns the quote body."""
    try:
        cert = dict(evidence["platform_cert"])
        cert_sig = cert.pop("sig")
        quote = evidence["quote"]
        signature = evidence["sig"]
    except (KeyError, TypeError) as exc:
        raise AttestationError(f"malformed evidence: {exc}") from None
    if not crypto.verify(vendor_root_public, cert_sig, crypto.canonical(cert)):
        raise AttestationError("platform certificate not issued by the vendor root")
    if quote.get("platform_id") != cert["platform_id"]:
        raise AttestationError("quote does not belong to the certified platform")
    if not crypto.verify(cert["att_pub"], signature, crypto.canonical(quote)):
        raise AttestationError("quote signature invalid")
    return quote


class Platform:
    def __init__(self, platform_id: str, attestation_key, cert: dict):
        self.platform_id = platform_id
        self.cert = cert
        self._attestation_key = attestation_key
        self._seal_root = os.urandom(32)

    def launch(self, app_cls, signer: str, host, isolation: bool = True, **app_args) -> "Enclave":
        return Enclave(self, app_cls, signer, host, isolation, app_args)

    def _quote(self, measurement: str, signer: str, report_data: bytes) -> dict:
        quote = {"platform_id": self.platform_id, "measurement": measurement,
                 "signer": signer, "report_data": report_data.hex()}
        return {"quote": quote, "sig": crypto.sign(self._attestation_key, crypto.canonical(quote)),
                "platform_cert": self.cert}

    def _seal_key(self, signer: str) -> bytes:
        return crypto.hkdf(self._seal_root, b"", b"seal|mrsigner|" + signer.encode())


class EnclaveServices:
    def __init__(self, enclave: "Enclave"):
        self._enclave = enclave

    @property
    def measurement(self) -> str:
        return self._enclave.measurement

    def quote(self, report_data: bytes) -> dict:
        e = self._enclave
        return e._platform._quote(e.measurement, e.signer, report_data)

    def seal(self, name: str, obj) -> None:
        e = self._enclave
        data = crypto.canonical(obj)
        if e.isolation:
            data = crypto.seal_bytes(e._platform._seal_key(e.signer), data, aad=name.encode())
        e._host.storage[name] = data

    def unseal(self, name: str):
        e = self._enclave
        data = e._host.storage[name]
        if e.isolation:
            data = crypto.open_bytes(e._platform._seal_key(e.signer), data, aad=name.encode())
        return json.loads(data)

    def expose(self, obj) -> None:
        """Without isolation, whatever the application handles is visible to the host."""
        if not self._enclave.isolation:
            self._enclave._host.memory.append(obj)

    def ocall(self, name: str, *args, **kwargs):
        return getattr(self._enclave._host, "ocall_" + name)(*args, **kwargs)


class Enclave:
    def __init__(self, platform: Platform, app_cls, signer: str, host, isolation: bool, app_args: dict):
        self._platform = platform
        self._host = host
        self.signer = signer
        self.isolation = isolation
        self._app_args = app_args
        self._load(app_cls)

    def _load(self, app_cls) -> None:
        self.app_cls = app_cls
        self.measurement = measure(app_cls)
        self._app = app_cls(EnclaveServices(self), **self._app_args)

    def ecall(self, name: str, *args, **kwargs):
        if name.startswith("_"):
            raise PermissionError("only public entry points are callable from the host")
        return getattr(self._app, name)(*args, **kwargs)

    def update(self, new_app_cls) -> None:
        """Replaces the code; sealed state survives because sealing is bound to the signer."""
        self._app.persist()
        self._load(new_app_cls)
