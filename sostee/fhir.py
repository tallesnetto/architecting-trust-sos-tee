"""Seeded generator of synthetic FHIR R4 resources (no real patient data)."""
import json
from pathlib import Path

GIVEN = ["Ana", "Bruno", "Carla", "Diego", "Elisa", "Fabio", "Gabriela", "Heitor", "Iara",
         "João", "Larissa", "Marcos", "Natália", "Otávio", "Paula", "Rafael", "Sofia", "Tiago"]
FAMILY = ["Almeida", "Barbosa", "Cardoso", "Dias", "Esteves", "Ferreira", "Gomes", "Lima",
          "Moreira", "Nascimento", "Oliveira", "Pereira", "Ribeiro", "Souza", "Teixeira"]
VITALS = [("8867-4", "Heart rate", "/min", 50, 130), ("59408-5", "Oxygen saturation", "%", 85, 100),
          ("8480-6", "Systolic blood pressure", "mm[Hg]", 90, 180),
          ("8462-4", "Diastolic blood pressure", "mm[Hg]", 50, 110),
          ("9279-1", "Respiratory rate", "/min", 10, 30), ("8310-5", "Body temperature", "Cel", 35, 40)]
PANEL = [("718-7", "Hemoglobin", "g/dL", 9, 17), ("4544-3", "Hematocrit", "%", 30, 52),
         ("6690-2", "Leukocytes", "10*3/uL", 3, 15), ("777-3", "Platelets", "10*3/uL", 120, 450),
         ("2345-7", "Glucose", "mg/dL", 60, 250), ("2160-0", "Creatinine", "mg/dL", 0.5, 2.5),
         ("2823-3", "Potassium", "mmol/L", 3, 6), ("2951-2", "Sodium", "mmol/L", 130, 150),
         ("3094-0", "Urea nitrogen", "mg/dL", 7, 40), ("1742-6", "ALT", "U/L", 7, 80)]
CONDITIONS = [("38341003", "Hypertensive disorder"), ("44054006", "Diabetes mellitus type 2"),
              ("195967001", "Asthma"), ("13645005", "Chronic obstructive lung disease"),
              ("49436004", "Atrial fibrillation")]


def patient(rng) -> dict:
    d = "".join(str(rng.randrange(10)) for _ in range(11))
    cpf = f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"
    return {"resourceType": "Patient", "id": f"pat-{rng.randrange(10**8):08d}",
            "identifier": [{"system": "urn:brasil:cpf", "value": cpf}],
            "name": [{"family": rng.choice(FAMILY), "given": [rng.choice(GIVEN)]}],
            "gender": rng.choice(["female", "male"]),
            "birthDate": f"{rng.randrange(1935, 2020)}-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"}


def _subject(p) -> dict:
    name = p["name"][0]
    return {"reference": f"Patient/{p['id']}", "display": f"{name['given'][0]} {name['family']}",
            "identifier": p["identifier"][0]}


def _observation(rng, p, code, display, unit, lo, hi, category) -> dict:
    return {"resourceType": "Observation", "id": f"obs-{rng.randrange(10**9)}", "status": "final",
            "category": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/observation-category",
                                      "code": category}]}],
            "code": {"coding": [{"system": "http://loinc.org", "code": code, "display": display}]},
            "subject": _subject(p),
            "valueQuantity": {"value": round(rng.uniform(lo, hi), 2), "unit": unit,
                              "system": "http://unitsofmeasure.org", "code": unit}}


def vital_signs(rng, p) -> dict:
    """Vital-signs Observation (size S)."""
    obs = _observation(rng, p, "85353-1", "Vital signs panel", "", 0, 0, "vital-signs")
    del obs["valueQuantity"]
    obs["component"] = [{"code": {"coding": [{"system": "http://loinc.org", "code": c, "display": d}]},
                         "valueQuantity": {"value": round(rng.uniform(lo, hi), 1), "unit": u}}
                        for c, d, u, lo, hi in VITALS]
    return obs


def lab_report(rng, p) -> dict:
    """Lab DiagnosticReport with ten results (size M)."""
    results = [_observation(rng, p, *a, "laboratory") for a in PANEL]
    return {"resourceType": "DiagnosticReport", "id": f"rep-{rng.randrange(10**9)}", "status": "final",
            "code": {"coding": [{"system": "http://loinc.org", "code": "24323-8",
                                 "display": "Comprehensive metabolic and blood panel"}]},
            "subject": _subject(p), "contained": results,
            "result": [{"reference": "#" + r["id"]} for r in results],
            "conclusion": "Automatically generated synthetic report."}


def history_bundle(rng, p, encounters: int = 12) -> dict:
    """Patient-history Bundle (size L)."""
    entries = [{"resource": p}]
    for code, display in rng.sample(CONDITIONS, 2):
        entries.append({"resource": {"resourceType": "Condition", "id": f"cond-{rng.randrange(10**9)}",
                                     "code": {"coding": [{"system": "http://snomed.info/sct",
                                                          "code": code, "display": display}]},
                                     "subject": _subject(p)}})
    for _ in range(encounters):
        entries.append({"resource": {"resourceType": "Encounter", "id": f"enc-{rng.randrange(10**9)}",
                                     "status": "finished", "subject": _subject(p)}})
        entries.append({"resource": vital_signs(rng, p)})
        entries.append({"resource": lab_report(rng, p)})
    return {"resourceType": "Bundle", "type": "collection", "entry": entries}


SIZES = {"S": vital_signs, "M": lab_report, "L": history_bundle}


def sensitive_markers(p) -> set:
    """Strings that identify the patient; finding one in host data means a leak."""
    name = p["name"][0]
    return {f"{name['given'][0]} {name['family']}", p["identifier"][0]["value"]}


def load_synthea(folder):
    """Yields the resources of Synthea FHIR bundles found in `folder`."""
    for path in sorted(Path(folder).glob("*.json")):
        bundle = json.loads(path.read_text(encoding="utf-8"))
        for entry in bundle.get("entry", []):
            yield entry["resource"]
