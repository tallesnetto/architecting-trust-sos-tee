"""E2: time per record exchange, record size on the wire and channel setup time.

The baseline and the full model are interleaved exchange by exchange, and the
garbage collector is paused while timing.

    python -m experiments.e2_overhead [--records N] [--warmup N] [--handshakes N]
"""
import argparse
import gc
import time

from sostee import crypto, fhir
from sostee.config import ABLATIONS
from sostee.sos import HealthSoS

from .common import rng_for, write_csv

CONFIGS = ["B0", "FULL"]


def _timed(fn):
    t0 = time.perf_counter_ns()
    result = fn()
    return result, (time.perf_counter_ns() - t0) / 1000


def run(records: int = 100, warmup: int = 10, n_handshakes: int = 30) -> None:
    order = rng_for("E2-order")
    cells = {}
    for name in CONFIGS:
        for size, make in fhir.SIZES.items():
            rng = rng_for("E2", name, size)
            sos = HealthSoS(ABLATIONS[name])
            sos.connect("hospital", "lab")
            cells[(name, size)] = (sos, [make(rng, fhir.patient(rng)) for _ in range(warmup + records)])
    links = {name: HealthSoS(ABLATIONS[name]) for name in CONFIGS}

    rows, hs_rows = [], []
    gc.collect()
    gc.disable()
    try:
        for i in range(warmup + records):
            keys = list(cells)
            order.shuffle(keys)
            for name, size in keys:
                sos, payloads = cells[(name, size)]
                result, us = _timed(lambda: sos["lab"].send(sos["hospital"], payloads[i]))
                assert result["accepted"], result
                if i >= warmup:
                    rows.append({"config": name, "size": size, "i": i - warmup, "latency_us": us,
                                 "wire_bytes": len(sos.network.capture[-1]),
                                 "payload_bytes": len(crypto.canonical(payloads[i]))})
            if i % 10 == 9:
                gc.collect()
        for i in range(1 + n_handshakes):
            names = list(CONFIGS)
            order.shuffle(names)
            for name in names:
                ok, us = _timed(lambda: links[name].connect("hospital", "lab"))
                if i:
                    hs_rows.append({"config": name, "i": i - 1, "ok": int(ok), "latency_us": us})
    finally:
        gc.enable()
    print("E2 done", flush=True)
    write_csv("e2_exchange.csv", rows)
    write_csv("e2_handshake.csv", hs_rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--handshakes", type=int, default=30)
    a = parser.parse_args()
    run(a.records, a.warmup, a.handshakes)
