"""Configurations: the conventional baseline (B0), the full model and single-decision variants."""
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Config:
    enclave: bool = True        # DP2 processing in the enclave, sealing
    sign_enclave: bool = True   # DP3 record signing
    reattest: bool = True       # DP4 continuous attestation
    gov_refvals: bool = True    # DP5 reference values published by the governance
    attest: bool = True         # DP1 attestation in the channel handshake
    did: bool = True            # institutional identity (DIDs and credentials)
    reattest_interval: float = 30.0


FULL = Config()
BASELINE = Config(enclave=False, sign_enclave=False, reattest=False, gov_refvals=False,
                  attest=False, did=False)

ABLATIONS = {
    "B0": BASELINE,
    "FULL": FULL,
    "-DA1": replace(FULL, enclave=False),
    "-DA2": replace(FULL, sign_enclave=False),
    "-DA3": replace(FULL, reattest=False),
    "-DA4": replace(FULL, gov_refvals=False),
    "-DA5": replace(FULL, attest=False),
    "-DA6": replace(FULL, did=False),
    "-DA1,2,6": replace(FULL, enclave=False, sign_enclave=False, did=False),
}
