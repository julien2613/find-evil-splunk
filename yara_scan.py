#!/usr/bin/env python3
"""YARA-X scan of a memory image → NDJSON for Splunk ingestion (artifacts/yara_hits.ndjson).

Scans the image via mmap (constant memory — no full load into RAM) using the YARA-X Python
bindings, and writes one NDJSON line listing the matching rules, each enriched with its
metadata (severity, MITRE technique, description). Consumed by ingest_to_splunk.py.

Usage:
    python yara_scan.py [--image IMG] [--rules RULES.yar] [--out FILE]
    # or: MEMORY_IMAGE=/path/to/image.img python yara_scan.py
"""
import argparse
import json
import logging
import mmap
import os
import sys
import time
from pathlib import Path

import yara_x

LOG = logging.getLogger("find_evil.yara")
BASE = Path(__file__).resolve().parent
DEFAULT_IMAGE = os.environ.get(
    "MEMORY_IMAGE", "/Users/julientaste/Downloads/base-dc-memory/base-dc-memory.img")


def scan(image: Path, rules_file: Path):
    """Compile the rules and scan the image; returns (matched_rules, elapsed_seconds)."""
    try:
        rules = yara_x.compile(rules_file.read_text())
    except Exception as e:  # yara_x.CompileError (class name varies across versions)
        sys.exit(f"YARA-X rule compilation failed ({rules_file}): {e}")

    scanner = yara_x.Scanner(rules)
    t0 = time.time()
    with image.open("rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            results = scanner.scan(mm)
        finally:
            mm.close()
    elapsed = time.time() - t0

    matched = []
    for rule in results.matching_rules:
        meta = dict(rule.metadata)
        total = sum(len(p.matches) for p in rule.patterns)
        matched.append({
            "identifier": rule.identifier,
            "severity": meta.get("severity", "unknown"),
            "mitre": meta.get("mitre", ""),
            "description": meta.get("description", ""),
            "matches": total,
        })
    return matched, elapsed


def main():
    ap = argparse.ArgumentParser(description="YARA-X scan of a memory image → NDJSON")
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--rules", default=str(BASE / "rules/apt_detection_rules.yar"))
    ap.add_argument("--out", default=str(BASE / "artifacts/yara_hits.ndjson"))
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    image, rules_file, out = Path(args.image), Path(args.rules), Path(args.out)
    if not rules_file.exists():
        sys.exit(f"Rules file not found: {rules_file}")
    if not image.exists():
        sys.exit(f"Memory image not found: {image} (set --image or MEMORY_IMAGE)")
    out.parent.mkdir(parents=True, exist_ok=True)

    LOG.info("scanning %s against %s …", image.name, rules_file.name)
    matched, elapsed = scan(image, rules_file)
    # NDJSON: one line, the matched rules (ingest_to_splunk.py reads rules[].identifier).
    line = {"image": image.name, "scan_seconds": round(elapsed, 1), "rules": matched}
    out.write_text(json.dumps(line) + "\n")
    LOG.info("%d rules matched in %.0fs → %s", len(matched), elapsed, out)


if __name__ == "__main__":
    main()
