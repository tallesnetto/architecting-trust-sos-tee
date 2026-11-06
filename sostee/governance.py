"""Governance of the acknowledged SoS: membership credentials and approved gateway versions."""
from .did import Identity, Registry

REFVALS_URL = "https://gov.sos.example/reference-values.json"
VALIDITY = 365 * 24 * 3600.0


class Governance:
    def __init__(self, registry: Registry, clock, did: str = "did:web:gov.sos.example"):
        self.registry = registry
        self.clock = clock
        self.identity = Identity(did, registry)
        self.accepted = []

    @property
    def did(self) -> str:
        return self.identity.did

    def admit(self, subject_did: str, role: str) -> dict:
        now = self.clock.now()
        return self.identity.issue(subject_did, "SoSMembershipCredential", {"role": role},
                                   now, now + VALIDITY)

    def accept_version(self, measurement: str, version: str) -> None:
        self.accepted.append({"measurement": measurement, "version": version})
        now = self.clock.now()
        vc = self.identity.issue(self.did, "ReferenceValuesCredential",
                                 {"referenceValues": list(self.accepted)}, now, now + VALIDITY)
        self.registry.publish(REFVALS_URL, vc)
