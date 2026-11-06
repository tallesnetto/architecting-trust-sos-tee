"""python -m unittest discover -s tests -t ."""
import random
import unittest
from dataclasses import replace

from sostee import crypto, fhir
from sostee.config import ABLATIONS, BASELINE, FULL
from sostee.did import CredentialError, Identity, Registry, verify_credential
from sostee.scenarios import SCENARIOS
from sostee.simtee import AttestationError, Vendor, measure, verify_evidence
from sostee.sos import HealthSoS
from sostee.trusted_app import TrustedGatewayApp
from sostee.trusted_app_v2 import TrustedGatewayAppV2
from sostee.variants import TamperingApp


class _Host:
    def __init__(self):
        self.storage, self.memory = {}, []


class _App:
    def __init__(self, svc):
        self.svc = svc

    def persist(self):
        pass


class _AppV2(_App):
    pass


class SimTEETest(unittest.TestCase):
    def test_measurement_is_deterministic_and_code_sensitive(self):
        self.assertEqual(measure(TrustedGatewayApp), measure(TrustedGatewayApp))
        self.assertNotEqual(measure(TrustedGatewayApp), measure(TrustedGatewayAppV2))
        self.assertNotEqual(measure(TrustedGatewayApp), measure(TamperingApp))

    def test_quote_verifies_only_under_the_vendor_root(self):
        vendor = Vendor()
        enclave = vendor.provision("p1").launch(_App, "signer", _Host())
        evidence = enclave._app.svc.quote(b"data")
        quote = verify_evidence(evidence, vendor.root_public)
        self.assertEqual(quote["report_data"], b"data".hex())
        self.assertEqual(quote["measurement"], measure(_App))
        with self.assertRaises(AttestationError):
            verify_evidence(evidence, Vendor().root_public)
        evidence["quote"]["measurement"] = "0" * 64
        with self.assertRaises(AttestationError):
            verify_evidence(evidence, vendor.root_public)

    def test_sealed_data_is_opaque_and_tamper_evident(self):
        host = _Host()
        svc = Vendor().provision("p1").launch(_App, "signer", host)._app.svc
        svc.seal("x", {"secret": "Maria"})
        self.assertNotIn(b"Maria", host.storage["x"])
        self.assertEqual(svc.unseal("x"), {"secret": "Maria"})
        host.storage["x"] = host.storage["x"][:-1] + bytes([host.storage["x"][-1] ^ 1])
        with self.assertRaises(crypto.InvalidTag):
            svc.unseal("x")

    def test_sealed_state_survives_update_with_same_signer(self):
        host = _Host()
        enclave = Vendor().provision("p1").launch(_App, "signer", host)
        enclave._app.svc.seal("k", [1, 2])
        enclave.update(_AppV2)
        self.assertNotEqual(enclave.measurement, measure(_App))
        self.assertEqual(enclave._app.svc.unseal("k"), [1, 2])

    def test_host_cannot_call_private_entry_points(self):
        enclave = Vendor().provision("p1").launch(_App, "signer", _Host())
        with self.assertRaises(PermissionError):
            enclave.ecall("_anything")


class DidTest(unittest.TestCase):
    def test_credential_validation(self):
        registry = Registry()
        issuer = Identity("did:web:gov.example", registry)
        Identity("did:web:a.example", registry)
        vc = issuer.issue("did:web:a.example", "SoSMembershipCredential", {"role": "lab"}, 0, 100)
        subject = verify_credential(registry, vc, 50, issuer.did, "SoSMembershipCredential")
        self.assertEqual(subject["role"], "lab")
        for now, iss, kind in [(150, issuer.did, "SoSMembershipCredential"),
                               (50, "did:web:a.example", "SoSMembershipCredential"),
                               (50, issuer.did, "OtherCredential")]:
            with self.assertRaises(CredentialError):
                verify_credential(registry, vc, now, iss, kind)
        vc["credentialSubject"]["role"] = "hospital"
        with self.assertRaises(CredentialError):
            verify_credential(registry, vc, 50, issuer.did, "SoSMembershipCredential")


class ArchitectureTest(unittest.TestCase):
    def test_legitimate_flow_in_every_configuration(self):
        for name, cfg in ABLATIONS.items():
            with self.subTest(config=name):
                rng = random.Random(name)
                sos = HealthSoS(cfg)
                self.assertTrue(sos.connect("hospital", "lab"))
                report = fhir.lab_report(rng, fhir.patient(rng))
                result = sos["lab"].send(sos["hospital"], report)
                self.assertTrue(result["accepted"], result)
                self.assertEqual(sos["hospital"].enclave.ecall("query", "care"), [report])
                self.assertEqual(sos["hospital"].enclave.ecall("query", "marketing"), [])

    def test_full_architecture_blocks_every_misuse_case(self):
        for scenario, fn in SCENARIOS.items():
            with self.subTest(scenario=scenario):
                self.assertFalse(fn(FULL, random.Random(scenario))["success"])

    def test_baseline_is_harmed_except_by_transit_tampering(self):
        harmed = {s for s, fn in SCENARIOS.items() if fn(BASELINE, random.Random(s))["success"]}
        self.assertEqual(harmed, {"CUI1", "CUI2", "CUI3b", "CUI3c", "CUI4", "CUI5"})

    def test_reattestation_detects_within_one_interval(self):
        from sostee.scenarios import run_compromise
        for T in (5.0, 30.0):
            res = run_compromise(replace(FULL, reattest_interval=T), random.Random(T), 100.5, 100.5 + T + 2)
            self.assertIsNotNone(res["detected_at"])
            self.assertLessEqual(res["detected_at"] - 100.5, T)


if __name__ == "__main__":
    unittest.main()
