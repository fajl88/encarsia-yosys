#!/usr/bin/env python3
"""Rewrite verification_summary.json timing buckets to be non-overlapping.

Legacy summaries used an overlapped `timing_ms.sensitization` bucket that
included propagation time. This script preserves the legacy timing block in
`timing_ms_legacy` and rewrites `timing_ms.sensitization` so that:

  preprocess + sensitization + propagation ~= total

Usage:
  python3 misc/fix_verification_summary_timing.py /encarsia-meta/out/Injection5/ibex
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def as_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    return 0


def migrate_one(path: Path) -> bool:
    data = json.loads(path.read_text())
    timing = data.get("timing_ms")
    if not isinstance(timing, dict):
        return False

    preprocess = as_int(timing.get("preprocess"))
    propagation = as_int(timing.get("propagation"))
    total = as_int(timing.get("total"))
    legacy_sensitization = as_int(timing.get("sensitization"))

    corrected_sensitization = total - preprocess - propagation
    if corrected_sensitization < 0:
        corrected_sensitization = 0
    if corrected_sensitization > legacy_sensitization:
        corrected_sensitization = legacy_sensitization

    data["timing_ms_legacy"] = dict(timing)
    data["timing_ms"] = {
        "preprocess": preprocess,
        "sensitization": corrected_sensitization,
        "propagation": propagation,
        "total": total,
    }
    data["timing_note"] = (
        "timing_ms.sensitization rewritten to non-overlapping bucket; "
        "legacy values preserved in timing_ms_legacy"
    )

    path.write_text(json.dumps(data, indent=2) + "\n")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Root directory to scan recursively")
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.exists():
        raise SystemExit(f"Path does not exist: {root}")

    count = 0
    for json_path in root.glob("**/verification_summary.json"):
        if migrate_one(json_path):
            count += 1

    print(f"Updated {count} verification summary files under {root}")


if __name__ == "__main__":
    main()
