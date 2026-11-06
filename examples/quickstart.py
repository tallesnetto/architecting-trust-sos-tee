"""One legitimate exchange and one misuse case.

    python -m examples.quickstart
"""
import random

from sostee import fhir
from sostee.config import BASELINE, FULL
from sostee.scenarios import SCENARIOS
from sostee.sos import HealthSoS

rng = random.Random(42)

# legitimate exchange under the full model
sos = HealthSoS(FULL)
print("attested channel opened:", sos.connect("hospital", "lab"))
report = fhir.lab_report(rng, fhir.patient(rng))
result = sos["lab"].send(sos["hospital"], report)
print("record accepted:", result["accepted"])
print("records released for care:", len(sos["hospital"].enclave.ecall("query", "care")))
print("records released for marketing:", len(sos["hospital"].enclave.ecall("query", "marketing")))

# misuse case MC1 (divergent software)
for name, config in [("baseline", BASELINE), ("full model", FULL)]:
    outcome = SCENARIOS["CUI1"](config, random.Random(1))
    print(f"MC1 under the {name}:", "harm" if outcome["success"] else "blocked")
