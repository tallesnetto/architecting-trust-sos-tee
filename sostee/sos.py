"""The inter-institutional health SoS: four constituents, a governance body and a TEE vendor."""
import time

from .did import Identity, Registry
from .gateway import Clock, Gateway, Network
from .governance import Governance
from .simtee import Vendor, measure
from .trusted_app import VERSION, TrustedGatewayApp

INSTITUTIONS = {
    "hospital": ("did:web:hospital.saude.example", "hospital"),
    "ambulance": ("did:web:samu.saude.example", "ambulance-service"),
    "lab": ("did:web:lab.saude.example", "diagnostic-lab"),
    "ehr": ("did:web:ehr-cloud.example", "ehr-operator"),
}


class HealthSoS:
    def __init__(self, config, app_classes=None, did_overrides=None):
        self.config = config
        self.clock = Clock()
        self.registry = Registry()
        self.network = Network()
        self.vendor = Vendor()
        self.gov = Governance(self.registry, self.clock)
        self.gov.accept_version(measure(TrustedGatewayApp), VERSION)
        self.gw = {}
        for name, (did, role) in INSTITUTIONS.items():
            identity = Identity(did, self.registry)
            gw = Gateway(name, did, self.vendor.provision(name),
                         self.registry, self.clock, self.network, config, self.vendor.root_public,
                         self.gov.did, app_cls=(app_classes or {}).get(name, TrustedGatewayApp),
                         institution_did=(did_overrides or {}).get(name))
            gw.enclave.ecall("install_identity", identity.export_key())
            gw.enclave.ecall("install_membership", self.gov.admit(did, role))
            self.gw[name] = gw
        refvals = [r["measurement"] for r in self.gov.accepted]
        for a in self.gw.values():
            a.enclave.ecall("pin_reference_values", refvals)
            for b in self.gw.values():
                if a is not b:
                    a.enclave.ecall("pin_peer", b.name, b.transport_pub)
        self._attested = {}
        self.reattest_log = []

    def __getitem__(self, name) -> Gateway:
        return self.gw[name]

    def connect(self, verifier: str, peer: str) -> bool:
        ok = self.gw[verifier].connect(self.gw[peer])
        if ok:
            self._attested[(verifier, peer)] = self.clock.now()
        return ok

    def advance_to(self, t: float) -> None:
        """Moves the clock to t, running every re-attestation due on the way."""
        interval = self.config.reattest_interval
        while self.config.reattest:
            due = [(last + interval, pair) for pair, last in self._attested.items()
                   if last + interval <= t]
            if not due:
                break
            when, (verifier, peer) = min(due)
            self.clock.set(when)
            start = time.perf_counter()
            ok = self.gw[verifier].connect(self.gw[peer])
            self.reattest_log.append((when, verifier, peer, ok, time.perf_counter() - start))
            if ok:
                self._attested[(verifier, peer)] = when
            else:
                del self._attested[(verifier, peer)]
        self.clock.set(t)

    def suspended(self, verifier: str, peer: str) -> bool:
        status = self.gw[verifier].enclave.ecall("session_status", peer)
        return status is None or status["suspended"]
