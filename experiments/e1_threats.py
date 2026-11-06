"""E1: runs every scenario under the baseline and the full model.

    python -m experiments.e1_threats [--trials N] [--all-configs]
"""
import argparse
import json

from sostee.config import ABLATIONS
from sostee.scenarios import SCENARIOS

from .common import rng_for, write_csv


CONFIGS = ["B0", "FULL"]


def run(trials: int = 1, configs=CONFIGS) -> None:
    rows = []
    for scenario, fn in SCENARIOS.items():
        for name in configs:
            cfg = ABLATIONS[name]
            for trial in range(trials):
                result = fn(cfg, rng_for("E1", scenario, name, trial))
                success = result.pop("success")
                rows.append({"scenario": scenario, "config": name, "trial": trial,
                             "harm": int(success), "details": json.dumps(result)})
            harmed = sum(r["harm"] for r in rows[-trials:])
            print(f"E1 {scenario:6} {name:9} harm {harmed}/{trials}", flush=True)
    write_csv("e1_threats.csv", rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--all-configs", action="store_true")
    a = parser.parse_args()
    run(a.trials, list(ABLATIONS) if a.all_configs else CONFIGS)
