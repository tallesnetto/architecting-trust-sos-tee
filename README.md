# SoS-TEE: Proof of Concept

Proof of concept (PoC) of the paper
**"Towards Architecting Trust in Systems-of-Systems through Trusted Execution
Environments: A Conceptual Model and Proof of Concept"** (SESoS 2027).

The paper proposes a conceptual model that tells Systems-of-Systems (SoS)
architects **why, where and under which conditions** to use Trusted Execution
Environments (TEEs). This repository contains an architecture for an
inter-institutional **health SoS** built in conformance with that model, the
misuse-case scenarios used to evaluate it, and the scripts that regenerate every
table and number reported in the paper.

> **Scope.** This is a *proof of concept*. It shows that the model can be built
> and behaves as intended in a controlled setting. The TEE is **simulated**
> (see [What is simulated](#what-is-simulated-and-what-is-not)), and the code is
> not meant for production use or to protect real patient data.

---

## Contents

1. [Quick start](#quick-start)
2. [What the code does](#what-the-code-does)
3. [Repository layout](#repository-layout)
4. [From the conceptual model to the code](#from-the-conceptual-model-to-the-code)
5. [Running the tests](#running-the-tests)
6. [Reproducing the experiments of the paper](#reproducing-the-experiments-of-the-paper)
7. [Using the library](#using-the-library)
8. [What is simulated and what is not](#what-is-simulated-and-what-is-not)
9. [Extending the PoC](#extending-the-poc)
10. [Citation and license](#citation-and-license)

---

## Quick start

Requirements: **Python 3.10 or newer** (developed and tested with Python 3.14).
The only third-party dependency is the [`cryptography`](https://cryptography.io)
library.

```bash
git clone https://github.com/tallesnetto/architecting-trust-sos-tee.git
cd architecting-trust-sos-tee

# create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows (PowerShell or cmd)

pip install -r requirements.txt

python -m unittest discover -s tests -t . -v    # 10 tests, about 2 s
python -m examples.quickstart                   # a short guided example
python -m experiments.run_all                   # all experiments of the paper, about 10 s
```

All commands must be run from the root of the repository, because the packages
are imported as `sostee`, `experiments` and `examples`.

---

## What the code does

The PoC simulates a regional health network with four independent institutions
(the *constituents* of the SoS), a governance body and a TEE vendor:

| Constituent | Role in the scenarios |
|---|---|
| Hospital | consumes records (lab reports, vital signs, histories) |
| Ambulance service | sends vital signs |
| Laboratory | issues lab reports |
| Third-party EHR cloud | holds records in custody for the others |

Each institution runs an **integration gateway**, the only component that talks
to the other institutions. Following the model, the TEE is placed only there:

```
              TEE vendor            Governance              DID registry
            (root of trust)   (members, approved versions)   (did:web)
                  :                      |                       :
   +--------------:----------+           |          +------------:-------------+
   |  Laboratory gateway     |                      |  Hospital gateway        |
   |  +-------------------+  |  attested channel,   |  +-------------------+   |
   |  | Enclave           |<-+----------------------+->| Enclave           |   |
   |  | trusted app,      |  |  re-attested every T |  | trusted app,      |   |
   |  | DID key           |  |  signed records      |  | DID key           |   |
   |  +-------------------+  |                      |  +-------------------+   |
   |  Host: storage, network |                      |  Host: storage, network  |
   +-------------------------+                      +--------------------------+
        internal systems                                 internal systems
```

* The **trusted application** (`sostee/trusted_app.py`) runs inside the enclave.
  It opens attested channels, signs and verifies records, seals stored data and
  applies the agreed handling rules (for example, data may be used for care but
  not for marketing).
* The **host** (`sostee/gateway.py`) is untrusted. It only provides storage
  (which receives sealed data) and networking, and reaches the trusted
  application through `ecall`s.
* The **governance** (`sostee/governance.py`) admits members and publishes, as
  a verifiable credential, the measurements of the gateway versions that apply
  the agreed rules.
* Each institution has a **decentralized identifier** (`did:web`, `sostee/did.py`)
  whose private key is provisioned into its enclave at integration.

A typical exchange: the laboratory's trusted application produces a FHIR lab
report and signs it; the record crosses an encrypted channel whose keys are bound
to attestation evidence; the hospital's trusted application decrypts it, checks
the signatures and the sender's identity, and seals it before storage.

---

## Repository layout

```
sostee/                 the architecture (library)
  simtee.py             SimTEE: simulated TEE (vendor root, measurement, quotes,
                        sealing, ecall/ocall boundary)
  trusted_app.py        trusted gateway application that runs in the enclave
  trusted_app_v2.py     version 2.0 of the trusted application (agreed update, EV1)
  variants.py           divergent gateway code used by the misuse cases
  gateway.py            untrusted host side of a gateway, network and logical clock
  sos.py                HealthSoS: builds and integrates the whole health SoS
  did.py                DIDs (did:web registry) and verifiable credentials
  governance.py         governance body of the acknowledged SoS
  config.py             configurations: baseline, full model, one decision off
  scenarios.py          misuse cases MC1-MC5 and the agreed update EV1
  fhir.py               seeded generator of synthetic FHIR resources
  crypto.py             thin wrapper over `cryptography` (Ed25519, X25519, HKDF, AES-GCM)
experiments/            experiments of the paper
  e1_threats.py         E1: runs every scenario under each configuration
  e2_overhead.py        E2: cost per record and per channel setup
  e3_interval.py        optional: effect of the re-attestation interval T (not in the paper)
  report.py             turns raw CSV results into LaTeX tables and in-text numbers
  run_all.py            runs E1 and E2 and the report in one command
  common.py             paths, seeding, CSV helpers, environment capture
examples/quickstart.py  short guided example of the library
tests/test_sostee.py    unit and scenario tests
results/                raw data of the run reported in the paper (CSV, JSON)
requirements.txt        pinned dependency
```

---

## From the conceptual model to the code

The conceptual model derives requirements from the defining properties of an
SoS and satisfies them with five design principles (DP). Each principle is
realized by one architectural decision, which can be switched on or off with a
flag of `sostee.config.Config`:

| Design principle (paper) | Architectural decision | `Config` flag | Main code | Misuse case |
|---|---|---|---|---|
| DP1 attestation anchored in hardware | attestation evidence embedded in the channel handshake | `attest` | `trusted_app.py`: `hs_offer`, `_verify_hello` | MC1 |
| DP2 processing inside the enclave | data decrypted only in the enclave; storage sealed | `enclave` | `simtee.py`: `seal`, `expose`; `trusted_app.py`: `consume` | MC2 |
| DP3 record signing | records signed with an attested enclave key | `sign_enclave` | `trusted_app.py`: `produce`, `_verify_envelope` | MC3a-c |
| DP4 continuous attestation | periodic re-attestation every `reattest_interval` seconds | `reattest` | `sos.py`: `advance_to` | MC4 |
| DP5 embedded external policies | governance publishes reference values of compliant versions | `gov_refvals` | `governance.py`; `trusted_app.py`: `_accepted_measurements`, `POLICY`, `query` | MC5, EV1 |
| (complementary) institutional identity | DIDs and membership credentials | `did` | `did.py`; `trusted_app.py`: `_check_did` | MC3c |

Ready-made configurations (`sostee/config.py`):

* `BASELINE`: a conventional, mutually authenticated and encrypted channel
  with keys pinned at integration (as in mTLS), and none of the decisions above.
* `FULL`: every decision enabled. This is the instantiated model.
* `ABLATIONS`: a dictionary with the two above plus the full model with one
  decision switched off (`"-DA1"` ... `"-DA6"`), used for exploration only.

### Misuse cases

Each misuse case (MC) is the health-SoS version of a misuse case derived by the
model and is numbered after the requirement it threatens. In the code they keep
the acronym of the original thesis, **CUI** (*caso de uso indesejado*, Portuguese
for misuse case).

| Paper | Code (`SCENARIOS`) | What the attacker does | Harm means |
|---|---|---|---|
| MC1 | `CUI1` | replaces the hospital gateway with software that copies received records elsewhere | the copied records reach the unauthorized destination |
| MC2 | `CUI2` | the EHR cloud operator searches memory, disk and traffic of its own host | patient identifiers are found |
| MC3a | `CUI3a` | a network adversary flips bits in, or replays, ambulance messages | a forged message is accepted |
| MC3b | `CUI3b` | the EHR cloud operator alters stored lab results | the hospital accepts an altered result |
| MC3c | `CUI3c` | an ambulance-service insider runs the agreed gateway with the lab's identity | a forged lab report is accepted as coming from the lab |
| MC4 | `CUI4` | the lab gateway is replaced by code that falsifies values after integration | the change is never detected |
| MC5 | `CUI5` | the hospital gateway ignores purpose limitation and serves a marketing query | data is released for marketing |
| EV1 | `EV1` | the governance approves version 2.0 and the lab installs it (legitimate) | the legitimate update is rejected |

Every scenario builds a fresh SoS from a seed, modifies one component in the way
the attacker would, and returns a dictionary whose key `success` tells whether
the harm happened.

---

## Running the tests

```bash
python -m unittest discover -s tests -t .        # summary
python -m unittest discover -s tests -t . -v     # one line per test
python -m unittest tests.test_sostee.ArchitectureTest   # a single test class
```

| Test class | What it checks |
|---|---|
| `SimTEETest` | the measurement changes whenever the code changes; quotes verify only under the vendor root and fail if altered; sealed data is opaque and tamper-evident and survives an update by the same signer; the host cannot call private entry points |
| `DidTest` | verifiable credentials are rejected when expired, issued by the wrong party, of the wrong type or altered |
| `ArchitectureTest` | a legitimate exchange works in every configuration and purpose limitation holds; the full model blocks every misuse case; the baseline is harmed in every misuse case except tampering in transit; re-attestation detects a change within one interval |

Expected output ends with `Ran 10 tests ... OK`.

---

## Reproducing the experiments of the paper

```bash
python -m experiments.run_all
```

This single command runs both experiments of the paper once, records the
execution environment and regenerates every table and in-text number:

| Experiment | Command (individually) | What it measures | Raw data |
|---|---|---|---|
| E1 scenarios | `python -m experiments.e1_threats` | outcome of each scenario under the baseline and the full model | `results/e1_threats.csv` |
| E2 cost | `python -m experiments.e2_overhead` | median time to deliver one record (sizes S, M, L), size of a record on the wire, time to open an attested channel | `results/e2_exchange.csv`, `results/e2_handshake.csv` |
| Report | `python -m experiments.report` | builds the LaTeX tables and macros from the CSV files | `generated/*.tex` |

`results/environment.json` records the Python version, platform, processor,
library version and protocol parameters of the run.

**Record sizes used in E2** (synthetic FHIR resources): S = vital signs
(about 1.3 KiB), M = lab report with ten results (about 5.7 KiB),
L = patient history (about 87.5 KiB).

**Where the outputs go.** CSV files are written to `results/`. LaTeX artifacts
(`e1_table.tex`, `e2_table.tex`, `macros.tex`) are written to `generated/`, or
to `../paper/generated/` when the repository sits next to the paper sources.

**Determinism.** Every input (keys aside) comes from a random generator seeded by
the experiment and scenario names, so E1 outcomes are reproducible exactly.
Scenario outcomes are decided by checks that either pass or fail (signatures,
quotes, measurements), so a single execution per scenario is enough. To repeat
each scenario with several seeds:

```bash
python -m experiments.e1_threats --trials 30
```

E2 timings depend on the machine and its load. To keep drift from favoring one
configuration, the two configurations are interleaved exchange by exchange and
the garbage collector is paused while timing. Absolute values will differ from
the paper; the relative difference between baseline and full model is what the
paper discusses.

**Optional explorations (not part of the paper).**

```bash
python -m experiments.e1_threats --all-configs   # also runs the full model with each decision switched off
python -m experiments.e2_overhead --records 1000 # more exchanges per size
python -m experiments.e3_interval                # detection latency and cost for several intervals T
```

---

## Using the library

`examples/quickstart.py` runs the following steps:

```python
import random
from sostee import fhir
from sostee.config import BASELINE, FULL
from sostee.scenarios import SCENARIOS
from sostee.sos import HealthSoS

rng = random.Random(42)

# A health SoS instantiating the full model
sos = HealthSoS(FULL)
sos.connect("hospital", "lab")                         # attested channel
report = fhir.lab_report(rng, fhir.patient(rng))       # synthetic FHIR lab report
result = sos["lab"].send(sos["hospital"], report)      # produce, transmit, verify, seal
print(result["accepted"])                              # True

sos["hospital"].enclave.ecall("query", "care")         # [report]: allowed purpose
sos["hospital"].enclave.ecall("query", "marketing")    # []: purpose not allowed

# A misuse case under the baseline and the full model
SCENARIOS["CUI1"](BASELINE, random.Random(1))["success"]   # True  (harm)
SCENARIOS["CUI1"](FULL, random.Random(1))["success"]       # False (blocked)
```

Other useful entry points:

* `HealthSoS(config).advance_to(t)` moves the logical clock to `t` seconds and
  runs every re-attestation due on the way; `sos.suspended("hospital", "lab")`
  tells whether a channel was suspended after a failed re-attestation.
* `dataclasses.replace(FULL, reattest_interval=60.0)` creates a configuration
  with another re-attestation interval.
* `fhir.load_synthea(folder)` yields resources from real
  [Synthea](https://synthetichealth.github.io/synthea/) FHIR bundles, if you
  prefer them to the built-in generator.

---

## What is simulated and what is not

**Real.** All cryptography (Ed25519 signatures, X25519 key agreement, HKDF,
AES-GCM), the channel protocol, record signing and verification, verifiable
credentials, the governance logic, and the handling rules of the trusted
application.

**Simulated (SimTEE).** The TEE reproduces the *trust relationships and
interfaces* of Intel SGX with DCAP attestation:

* a vendor root that certifies one attestation key per platform;
* a measurement computed as SHA-256 over the **actual source code** of the
  trusted application, so changing any line of it changes the measurement;
* quotes that bind caller-chosen data (such as a channel key) to the measurement;
* sealing keys bound to the signer identity, so sealed state survives updates;
* an `ecall`/`ocall` boundary between host and enclave.

**Assumed, not enforced.** Hardware isolation: in Python, nothing prevents code
from reading the enclave's memory. The architecture assumes, as the conceptual
model does, that the hardware root of trust is not compromised. When the enclave
decision is switched off, the code mirrors every plaintext into host-readable
memory, to emulate an application that runs outside a TEE.

**Consequences.** The cost figures cover the protocol of the model only. They
exclude enclave transitions, encrypted-memory paging and quote generation by real
hardware. Side channels and hardware attacks are out of scope. Porting the trusted
application to Intel SGX (for example with Gramine) is future work.

All the data are **synthetic**; no real patient data is used or included.

---

## Extending the PoC

* **New misuse case.** Write a function `my_case(cfg, rng) -> {"success": bool, ...}`
  in `sostee/scenarios.py` that builds a `HealthSoS(cfg)`, modifies one component
  (often by passing a subclass of `TrustedGatewayApp` through `app_classes`, as
  in `variants.py`) and reports whether the harm happened. Add it to `SCENARIOS`;
  E1 will run it automatically. To include it in the paper table, add a row to
  `SCENARIO_ROWS` in `experiments/report.py`.
* **New architectural decision.** Add a flag to `Config`, check it in the
  trusted application, and add an entry to `ABLATIONS`.
* **Another domain.** Replace `INSTITUTIONS` in `sos.py` and the resource
  generators in `fhir.py`; the trusted application only signs, encrypts and
  checks generic JSON resources.

---

## Citation and license

### Authors

* **Talles Netto Barros**, Federal University of Goiás, Goiânia, Brazil (tallesnetto@discente.ufg.br)
* **Rafael Z. Frantz**, Unijuí University, Ijuí, Brazil (rzfrantz@unijui.edu.br)
* **Mohamad Kassab**, University of Boston, Boston, USA (mkassab@bu.edu)
* **Valdemar V. Graciano Neto**, Federal University of Goiás, Goiânia, Brazil (valdemarneto@ufg.br)