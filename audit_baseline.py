#!/usr/bin/env python3
"""Build an aggregate peer/historical baseline for the offboarding dashboard."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from statistics import mean, pstdev

from aws_audit_report import load_rows


def build_baseline(paths: list[str], label: str) -> dict:
    per_file = []
    names = set()
    for path in paths:
        counts = Counter(str(row.get("event_name", "")) for row in load_rows(path))
        counts.pop("", None)
        per_file.append(counts)
        names.update(counts)
    events = {}
    for event_name in sorted(names):
        values = [counts.get(event_name, 0) for counts in per_file]
        events[event_name] = {
            "mean": round(mean(values), 3),
            "stddev": round(pstdev(values), 3),
            "minimum": min(values),
            "maximum": max(values),
        }
    return {
        "schema_version": 1,
        "label": label,
        "sample_size": len(per_file),
        "events": events,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a peer activity baseline from audit JSON/CSV files.")
    parser.add_argument("inputs", nargs="+", help="Peer or historical collector files.")
    parser.add_argument("--label", default="Peer baseline")
    parser.add_argument("--out", default="aws_offboarding.baseline.json")
    args = parser.parse_args(argv)
    baseline = build_baseline(args.inputs, args.label)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, sort_keys=True)
    print(f"Wrote {args.out} from {baseline['sample_size']} input file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())