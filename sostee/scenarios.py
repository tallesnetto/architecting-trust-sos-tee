"""Misuse cases CUI1-CUI5 (MC1-MC5 in the paper) and the agreed update EV1.

Each scenario returns {"success": bool, ...}; success means the harm happened
(for EV1, that a legitimate record was rejected).
"""
import json
from dataclasses import replace

from . import crypto, fhir
from .sos import INSTITUTIONS, HealthSoS
from .simtee import measure
from .trusted_app_v2 import TrustedGatewayAppV2
from .variants import ExfiltratingApp, NoPolicyApp, TamperingApp

N_RECORDS = 5


def cui1_divergent_software(cfg, rng):
    """The hospital runs a modified gateway that copies what it receives."""
    sos = HealthSoS(cfg, app_classes={"hospital": ExfiltratingApp})
    if sos.connect("lab", "hospital"):
        for _ in range(N_RECORDS):
            sos["lab"].send(sos["hospital"], fhir.lab_report(rng, fhir.patient(rng)))
    return {"success": len(sos["hospital"].exfiltrated) > 0}


def cui2_infrastructure_exposure(cfg, rng):
    """The EHR cloud operator searches host memory, disk and traffic."""
    sos = HealthSoS(cfg)
    markers = set()
    if sos.connect("lab", "ehr"):
        for _ in range(N_RECORDS):
            p = fhir.patient(rng)
            markers |= fhir.sensitive_markers(p)
            sos["lab"].send(sos["ehr"], fhir.lab_report(rng, p))
    ehr = sos["ehr"]
    memory = [crypto.canonical(obj) for obj in ehr.memory]
    dump = b"\n".join(memory + list(ehr.storage.values()) + sos.network.capture)
    leaked = sum(m.encode() in dump for m in markers)
    return {"success": leaked > 0, "leaked_fraction": leaked / len(markers)}


def cui3a_transit_tampering(cfg, rng):
    """A network adversary flips bits in, or replays, ambulance messages."""
    sos = HealthSoS(cfg)
    hospital, ambulance = sos["hospital"], sos["ambulance"]
    sos.connect("hospital", "ambulance")
    mode, seen = rng.choice(["bitflip", "replay"]), []

    def adversary(src, dst, msg):
        if "ct" in msg:
            seen.append(dict(msg))
            if mode == "bitflip":
                ct = bytearray(crypto.b64d(msg["ct"]))
                ct[rng.randrange(len(ct))] ^= 1 << rng.randrange(8)
                msg["ct"] = crypto.b64e(bytes(ct))
        return msg

    sos.network.interceptor = adversary
    accepted_forged = 0
    for _ in range(N_RECORDS):
        result = ambulance.send(hospital, fhir.vital_signs(rng, fhir.patient(rng)))
        accepted_forged += mode == "bitflip" and result["accepted"]
    if mode == "replay":
        sos.network.interceptor = None
        accepted_forged += hospital.receive("ambulance", rng.choice(seen))["accepted"]
    return {"success": accepted_forged > 0, "mode": mode}


def _admin_modifies(blob: bytes, rng) -> bytes:
    try:
        stored = json.loads(blob)
    except (ValueError, UnicodeDecodeError):
        b = bytearray(blob)
        b[rng.randrange(len(b))] ^= 0xFF
        return bytes(b)
    obs = rng.choice(stored["env"]["core"]["resource"]["contained"])
    obs["valueQuantity"]["value"] = round(obs["valueQuantity"]["value"] * rng.uniform(1.5, 3), 2)
    return crypto.canonical(stored)


def cui3b_tampering_at_custodian(cfg, rng):
    """The EHR operator alters stored lab reports before the hospital reads them."""
    sos = HealthSoS(cfg)
    lab, ehr, hospital = sos["lab"], sos["ehr"], sos["hospital"]
    sos.connect("lab", "ehr")
    sos.connect("hospital", "ehr")
    originals, ids = [], []
    for _ in range(N_RECORDS):
        report = fhir.lab_report(rng, fhir.patient(rng))
        result = lab.send(ehr, report)
        if result["accepted"]:
            originals.append(report)
            ids.append(result["id"])
    for key in [k for k in ehr.storage if k.startswith("record:")]:
        ehr.storage[key] = _admin_modifies(ehr.storage[key], rng)
    for rid in ids:
        hospital.request(ehr, rid)
    received = hospital.enclave.ecall("query", "care")
    return {"success": any(r not in originals for r in received)}


def cui3c_origin_forgery(cfg, rng):
    """An ambulance-service insider runs the agreed gateway with the lab's DID."""
    sos = HealthSoS(cfg, did_overrides={"ambulance": INSTITUTIONS["lab"][0]})
    accepted = 0
    if sos.connect("hospital", "ambulance"):
        for _ in range(N_RECORDS):
            result = sos["ambulance"].send(sos["hospital"], fhir.lab_report(rng, fhir.patient(rng)))
            accepted += result["accepted"] and result["origin"] == INSTITUTIONS["lab"][0]
    return {"success": accepted > 0}


def run_compromise(cfg, rng, t_compromise, horizon, new_app=TamperingApp, before_update=None):
    """The lab sends one record per second; its gateway code is replaced at t_compromise."""
    sos = HealthSoS(cfg)
    lab, hospital = sos["lab"], sos["hospital"]
    sos.connect("hospital", "lab")
    accepted_after = rejected_after = 0
    detected_at, updated = None, False
    t = 1
    while t <= horizon:
        if not updated and t >= t_compromise:
            sos.advance_to(t_compromise)
            if before_update:
                before_update(sos)
            lab.enclave.update(new_app)
            updated = True
        sos.advance_to(t)
        if updated and detected_at is None and sos.suspended("hospital", "lab"):
            detected_at = next(e[0] for e in reversed(sos.reattest_log) if not e[3])
        result = lab.send(hospital, fhir.vital_signs(rng, fhir.patient(rng)))
        if updated:
            accepted_after += result["accepted"]
            rejected_after += not result["accepted"]
        t += 1
    return {"detected_at": detected_at, "accepted_after": accepted_after,
            "rejected_after": rejected_after, "sos": sos}


def cui4_post_integration_compromise(cfg, rng):
    """The lab's gateway is replaced by tampering code after integration."""
    t_c = rng.uniform(60, 300)
    run = run_compromise(cfg, rng, t_c, t_c + 3 * cfg.reattest_interval)
    return {"success": run["detected_at"] is None, "accepted_after": run["accepted_after"]}


def cui5_secondary_use(cfg, rng):
    """The hospital's gateway ignores purpose limitation and serves a marketing query."""
    sos = HealthSoS(cfg, app_classes={"hospital": NoPolicyApp})
    if sos.connect("lab", "hospital"):
        for _ in range(N_RECORDS):
            sos["lab"].send(sos["hospital"], fhir.lab_report(rng, fhir.patient(rng)))
    return {"success": len(sos["hospital"].enclave.ecall("query", "marketing")) > 0}


def ev1_agreed_update(cfg, rng):
    """The governance approves version 2.0 and the lab installs it."""
    t_u = rng.uniform(60, 300)

    def publish_v2(sos):
        sos.gov.accept_version(measure(TrustedGatewayAppV2), "2.0")

    run = run_compromise(cfg, rng, t_u, t_u + 3 * cfg.reattest_interval,
                         new_app=TrustedGatewayAppV2, before_update=publish_v2)
    return {"success": run["rejected_after"] > 0, "rejected_after": run["rejected_after"]}


SCENARIOS = {
    "CUI1": cui1_divergent_software,
    "CUI2": cui2_infrastructure_exposure,
    "CUI3a": cui3a_transit_tampering,
    "CUI3b": cui3b_tampering_at_custodian,
    "CUI3c": cui3c_origin_forgery,
    "CUI4": cui4_post_integration_compromise,
    "CUI5": cui5_secondary_use,
    "EV1": ev1_agreed_update,
}
