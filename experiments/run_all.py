"""Runs E1 and E2 and regenerates the tables.

    python -m experiments.run_all
"""
import time

from . import e1_threats, e2_overhead, report
from .common import save_environment

PROTOCOL = {"e1_trials": 1, "e2_blocks": 5, "e2_records": 300, "e2_warmup": 20, "e2_handshakes": 30}


def main():
    p = PROTOCOL
    start = time.perf_counter()
    e1_threats.run(p["e1_trials"])
    e2_overhead.run(p["e2_blocks"], p["e2_records"], p["e2_warmup"], p["e2_handshakes"])
    save_environment({"protocol": p, "elapsed_s": round(time.perf_counter() - start, 1)})
    report.main()


if __name__ == "__main__":
    main()
