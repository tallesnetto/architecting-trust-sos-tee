"""E3 (optional, not in the paper): detection latency and cost for several re-attestation intervals.

    python -m experiments.e3_interval [--intervals T ...]
"""
import argparse
from dataclasses import replace

from sostee.config import FULL
from sostee.scenarios import run_compromise

from .common import rng_for, write_csv

INTERVALS = [1, 5, 15, 30, 60, 120, 300]


def run(intervals=INTERVALS) -> None:
    rows = []
    for T in intervals:
        cfg = replace(FULL, reattest_interval=float(T))
        rng = rng_for("E3", T)
        t_c = rng.uniform(300, 600)
        res = run_compromise(cfg, rng, t_c, t_c + T + 2)
        ok = [e[4] for e in res["sos"].reattest_log if e[3]]
        mean_cpu = sum(ok) / len(ok) if ok else 0.0
        detected = res["detected_at"]
        rows.append({"T": T, "t_c": round(t_c, 3), "detected_at": detected,
                     "D": round(detected - t_c, 3) if detected is not None else "",
                     "exposure": res["accepted_after"], "reattestations": len(ok),
                     "reattest_ms": round(mean_cpu * 1000, 4),
                     "cpu_ms_per_hour": round(mean_cpu * 1000 * 3600 / T, 2)})
        print(f"E3 T={T:4}s done", flush=True)
    write_csv("e3_interval.csv", rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intervals", type=int, nargs="*", default=INTERVALS)
    run(parser.parse_args().intervals)
