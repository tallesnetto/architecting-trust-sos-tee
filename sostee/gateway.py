"""Untrusted host side of an integration gateway, plus the network and the clock."""
import json

from . import crypto
from .trusted_app import Rejected, TrustedGatewayApp

SIGNER = "sos-consortium"


class Clock:
    def __init__(self):
        self._t = 0.0

    def now(self) -> float:
        return self._t

    def set(self, t: float) -> None:
        self._t = max(self._t, t)


class Network:
    """Records every message on the wire and lets an adversary rewrite it in transit."""

    def __init__(self):
        self.capture = []
        self.interceptor = None

    def transmit(self, src: str, dst: str, msg: dict) -> dict:
        wire = crypto.canonical(msg)
        self.capture.append(wire)
        msg = json.loads(wire)
        return self.interceptor(src, dst, msg) if self.interceptor else msg


class Gateway:
    def __init__(self, name, did, platform, registry, clock, network, config, vendor_root,
                 gov_did, app_cls=TrustedGatewayApp, institution_did=None):
        self.name = name
        self.did = did
        self.registry = registry
        self.clock = clock
        self.network = network
        self.storage = {}
        self.memory = []
        self.exfiltrated = []
        self._transport_key = crypto.new_signing_key()
        self.transport_pub = crypto.b64e(crypto.raw_public(self._transport_key))
        self.enclave = platform.launch(app_cls, SIGNER, self, isolation=config.enclave,
                                       institution_did=institution_did or did,
                                       config=config, vendor_root=vendor_root, gov_did=gov_did)

    def ocall_now(self):
        return self.clock.now()

    def ocall_transport_sign(self, data):
        return {"pub": self.transport_pub, "sig": crypto.sign(self._transport_key, data)}

    def ocall_resolve(self, did):
        return self.registry.resolve(did)

    def ocall_fetch(self, url):
        return self.registry.fetch(url)

    def ocall_exfiltrate(self, obj):
        self.exfiltrated.append(obj)

    def connect(self, peer: "Gateway") -> bool:
        offer = self.network.transmit(self.name, peer.name, self.enclave.ecall("hs_offer", peer.name))
        try:
            answer = peer.enclave.ecall("hs_accept", self.name, offer)
        except Rejected:
            self.enclave.ecall("hs_abort", peer.name)
            return False
        answer = self.network.transmit(peer.name, self.name, answer)
        try:
            self.enclave.ecall("hs_complete", peer.name, answer)
            return True
        except Rejected:
            return False

    def send(self, peer: "Gateway", resource: dict, purpose: str = "care") -> dict:
        try:
            msg = self.enclave.ecall("produce", peer.name, resource, purpose)
        except Rejected as r:
            return {"accepted": False, "reason": "sender: " + r.reason}
        return peer.receive(self.name, self.network.transmit(self.name, peer.name, msg))

    def receive(self, src: str, msg: dict) -> dict:
        return self.enclave.ecall("consume", src, msg)

    def request(self, custodian: "Gateway", record_id: str, purpose: str = "care") -> dict:
        try:
            msg = custodian.enclave.ecall("fetch", self.name, record_id, purpose)
        except Rejected as r:
            return {"accepted": False, "reason": "custodian: " + r.reason}
        return self.receive(custodian.name, self.network.transmit(custodian.name, self.name, msg))
