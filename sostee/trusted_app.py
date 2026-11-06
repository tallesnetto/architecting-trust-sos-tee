"""Trusted gateway application, the code that runs inside the enclave."""
import json

from . import crypto
from .did import CredentialError, did_proof, verify_credential, verify_did_signature
from .governance import REFVALS_URL
from .simtee import AttestationError, verify_evidence

VERSION = "1.0"

POLICY = {"allowed_purposes": ["care"], "retention_s": 7 * 24 * 3600}


class Rejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _RegistryView:
    def __init__(self, svc):
        self._svc = svc

    def resolve(self, did):
        return self._svc.ocall("resolve", did)

    def fetch(self, url):
        return self._svc.ocall("fetch", url)


def _binding(label: bytes, public: bytes) -> bytes:
    return crypto.sha256(label + b"|" + public)


class TrustedGatewayApp:
    def __init__(self, svc, institution_did, config, vendor_root, gov_did):
        self._svc = svc
        self._cfg = config
        self._vendor_root = vendor_root
        self._gov_did = gov_did
        self._registry = _RegistryView(svc)
        self._pending = {}
        self._refvals_cache = {}
        self.did = institution_did
        try:
            self._restore(svc.unseal("app-state"))
        except KeyError:
            self._sign_key = crypto.new_signing_key()
            self._sign_evidence = None
            self._sessions, self._pins, self._records = {}, {}, []
            self._membership, self._local_refvals, self._counter = None, [], 0
            self._did_key = None
        self._refresh_signing_evidence()

    def _refresh_signing_evidence(self):
        ev = self._sign_evidence
        if ev is None or ev["quote"]["measurement"] != self._svc.measurement:
            pub = crypto.raw_public(self._sign_key)
            self._sign_evidence = self._svc.quote(_binding(b"sign", pub))

    def persist(self):
        self._svc.seal("app-state", {
            "sign_key": crypto.b64e(crypto.signing_key_bytes(self._sign_key)),
            "sign_evidence": self._sign_evidence, "sessions": self._sessions, "pins": self._pins,
            "records": self._records, "membership": self._membership,
            "local_refvals": self._local_refvals, "counter": self._counter,
            "did_key": crypto.b64e(crypto.signing_key_bytes(self._did_key)) if self._did_key else None})

    def _restore(self, s):
        self._sign_key = crypto.signing_key_from_bytes(crypto.b64d(s["sign_key"]))
        self._sign_evidence = s["sign_evidence"]
        self._sessions, self._pins, self._records = s["sessions"], s["pins"], s["records"]
        self._membership, self._local_refvals, self._counter = (
            s["membership"], s["local_refvals"], s["counter"])
        self._did_key = crypto.signing_key_from_bytes(crypto.b64d(s["did_key"])) if s["did_key"] else None

    def install_membership(self, vc):
        self._membership = vc

    def install_identity(self, key):
        self._did_key = crypto.signing_key_from_bytes(crypto.b64d(key))

    def _did_sign(self, data):
        return did_proof(self.did, self._did_key, data)

    def pin_peer(self, peer, transport_public):
        self._pins[peer] = transport_public

    def pin_reference_values(self, measurements):
        self._local_refvals = list(measurements)

    def _now(self):
        return self._svc.ocall("now")

    def _accepted_measurements(self):
        if not self._cfg.gov_refvals:
            return set(self._local_refvals)
        vc = self._registry.fetch(REFVALS_URL)
        digest = crypto.sha256(crypto.canonical(vc))
        if digest not in self._refvals_cache:
            try:
                subject = verify_credential(self._registry, vc, self._now(), self._gov_did,
                                            "ReferenceValuesCredential")
            except CredentialError as exc:
                raise Rejected(f"reference values: {exc}") from None
            self._refvals_cache[digest] = {r["measurement"] for r in subject["referenceValues"]}
        return self._refvals_cache[digest]

    def _check_attestation(self, evidence, binding):
        try:
            quote = verify_evidence(evidence, self._vendor_root)
        except AttestationError as exc:
            raise Rejected(f"attestation: {exc}") from None
        if quote["report_data"] != binding.hex():
            raise Rejected("evidence not bound to the presented key")
        return quote["measurement"]

    def _check_did(self, did, proof, data, membership):
        if not verify_did_signature(self._registry, did, proof or {}, data):
            raise Rejected("DID signature invalid")
        try:
            subject = verify_credential(self._registry, membership or {}, self._now(),
                                        self._gov_did, "SoSMembershipCredential")
        except CredentialError as exc:
            raise Rejected(f"membership: {exc}") from None
        if subject["id"] != did:
            raise Rejected("membership credential issued to another subject")

    def _hello(self, eph):
        eph_pub = crypto.raw_public(eph)
        binding = _binding(b"ra-tls", eph_pub)
        hello = {"eph_pub": crypto.b64e(eph_pub), "did": self.did,
                 "transport": self._svc.ocall("transport_sign", binding)}
        if self._cfg.attest:
            hello["evidence"] = self._svc.quote(binding)
        if self._cfg.did:
            hello["did_proof"] = self._did_sign(binding)
            hello["membership"] = self._membership
        return hello

    def _verify_hello(self, peer, hello):
        eph_pub = crypto.b64d(hello["eph_pub"])
        binding = _binding(b"ra-tls", eph_pub)
        transport = hello.get("transport", {})
        if transport.get("pub") != self._pins.get(peer) or not crypto.verify(
                transport["pub"], transport.get("sig", ""), binding):
            raise Rejected("transport authentication failed")
        measurement = None
        if self._cfg.attest:
            measurement = self._check_attestation(hello.get("evidence"), binding)
            if measurement not in self._accepted_measurements():
                raise Rejected("peer runs code not accepted by the SoS")
        if self._cfg.did:
            self._check_did(hello.get("did"), hello.get("did_proof"), binding, hello.get("membership"))
        return eph_pub, hello.get("did"), measurement

    def _open_session(self, peer, eph, offer_pub, answer_pub, initiator, peer_did, measurement):
        shared = crypto.agree(eph, answer_pub if initiator else offer_pub)
        salt = crypto.sha256(offer_pub + answer_pub)
        i2r = crypto.hkdf(shared, salt, b"sostee|i2r")
        r2i = crypto.hkdf(shared, salt, b"sostee|r2i")
        send, recv = (i2r, r2i) if initiator else (r2i, i2r)
        self._sessions[peer] = {"send": crypto.b64e(send), "recv": crypto.b64e(recv),
                                "send_seq": 0, "recv_seq": 0, "peer_did": peer_did,
                                "measurement": measurement, "attested_at": self._now(),
                                "suspended": False}

    def _suspend(self, peer):
        if peer in self._sessions:
            self._sessions[peer]["suspended"] = True

    def hs_offer(self, peer):
        eph = crypto.new_ephemeral_key()
        self._pending[peer] = eph
        return self._hello(eph)

    def hs_accept(self, peer, offer):
        try:
            offer_pub, peer_did, measurement = self._verify_hello(peer, offer)
        except Rejected:
            self._suspend(peer)
            raise
        eph = crypto.new_ephemeral_key()
        self._open_session(peer, eph, offer_pub, crypto.raw_public(eph), False, peer_did, measurement)
        return self._hello(eph)

    def hs_complete(self, peer, answer):
        eph = self._pending.pop(peer)
        try:
            answer_pub, peer_did, measurement = self._verify_hello(peer, answer)
        except Rejected:
            self._suspend(peer)
            raise
        self._open_session(peer, eph, crypto.raw_public(eph), answer_pub, True, peer_did, measurement)

    def hs_abort(self, peer):
        self._pending.pop(peer, None)
        self._suspend(peer)

    def session_status(self, peer):
        s = self._sessions.get(peer)
        return None if s is None else {k: s[k] for k in ("peer_did", "measurement",
                                                         "attested_at", "suspended")}

    def _active(self, peer):
        s = self._sessions.get(peer)
        if s is None or s["suspended"]:
            raise Rejected("no active attested session with peer")
        return s

    def _encrypt(self, s, obj):
        s["send_seq"] += 1
        seq = s["send_seq"]
        ct = crypto.seal_bytes(crypto.b64d(s["send"]), crypto.canonical(obj), str(seq).encode())
        return {"seq": seq, "ct": crypto.b64e(ct)}

    def _decrypt(self, s, msg):
        seq = int(msg["seq"])
        if seq <= s["recv_seq"]:
            raise Rejected("replayed or reordered message")
        try:
            pt = crypto.open_bytes(crypto.b64d(s["recv"]), crypto.b64d(msg["ct"]), str(seq).encode())
        except (crypto.InvalidTag, ValueError):
            raise Rejected("channel integrity check failed") from None
        s["recv_seq"] = seq
        return json.loads(pt)

    def produce(self, peer, resource, purpose):
        s = self._active(peer)
        self._counter += 1
        core = {"id": f"{self.did}#{self._counter}", "origin": self.did,
                "produced_at": self._now(), "purpose": purpose, "resource": resource}
        digest = crypto.sha256(crypto.canonical(core))
        env = {"core": core}
        if self._cfg.sign_enclave:
            env["enclave_proof"] = {"pub": crypto.b64e(crypto.raw_public(self._sign_key)),
                                    "sig": crypto.sign(self._sign_key, digest),
                                    "evidence": self._sign_evidence}
        if self._cfg.did:
            env["did_proof"] = self._did_sign(digest)
            env["membership"] = self._membership
        self._svc.expose(env)
        return self._encrypt(s, env)

    def _verify_envelope(self, env):
        core = env["core"]
        digest = crypto.sha256(crypto.canonical(core))
        if self._cfg.sign_enclave:
            proof = env.get("enclave_proof") or {}
            if not crypto.verify(proof.get("pub", ""), proof.get("sig", ""), digest):
                raise Rejected("enclave signature invalid")
            measurement = self._check_attestation(
                proof.get("evidence"), _binding(b"sign", crypto.b64d(proof["pub"])))
            if self._cfg.attest and measurement not in self._accepted_measurements():
                raise Rejected("record produced by code not accepted by the SoS")
        if self._cfg.did:
            self._check_did(core["origin"], env.get("did_proof"), digest, env.get("membership"))

    def consume(self, peer, msg):
        try:
            s = self._active(peer)
            env = self._decrypt(s, msg)
            self._svc.expose(env)
            self._verify_envelope(env)
        except Rejected as r:
            return {"accepted": False, "reason": r.reason}
        rid = env["core"]["id"]
        self._svc.seal("record:" + rid, {"env": env, "received_at": self._now()})
        self._records.append(rid)
        return {"accepted": True, "id": rid, "origin": env["core"]["origin"]}

    def _load(self, rid):
        try:
            return self._svc.unseal("record:" + rid)
        except (KeyError, crypto.InvalidTag, ValueError):
            raise Rejected("record unavailable or modified at rest") from None

    def fetch(self, peer, rid, purpose):
        if purpose not in POLICY["allowed_purposes"]:
            raise Rejected("purpose not allowed by the sharing agreement")
        s = self._active(peer)
        env = self._load(rid)["env"]
        self._svc.expose(env)
        return self._encrypt(s, env)

    def query(self, purpose):
        if purpose not in POLICY["allowed_purposes"]:
            return []
        out, now = [], self._now()
        for rid in list(self._records):
            stored = self._load(rid)
            if now - stored["received_at"] > POLICY["retention_s"]:
                self._records.remove(rid)
                continue
            out.append(stored["env"]["core"]["resource"])
        return out
