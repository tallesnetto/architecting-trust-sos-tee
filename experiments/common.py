"""Paths, seeding and CSV helpers shared by the experiments."""
import csv
import json
import platform
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

POC = Path(__file__).resolve().parents[1]
RESULTS = POC / "results"
_PAPER = POC.parent / "paper"
GENERATED = _PAPER / "generated" if _PAPER.is_dir() else POC / "generated"


def rng_for(*parts) -> random.Random:
    return random.Random("|".join(map(str, parts)))


def write_csv(name: str, rows: list) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


def read_csv(name: str) -> list:
    with (RESULTS / name).open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_environment(extra: dict = None) -> None:
    import cryptography
    RESULTS.mkdir(parents=True, exist_ok=True)
    env = {"utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "python": sys.version, "platform": platform.platform(),
           "processor": platform.processor(), "cryptography": cryptography.__version__,
           **(extra or {})}
    (RESULTS / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
