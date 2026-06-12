#!/usr/bin/env python3
"""YARA-X scan of the memory image — JSON output for Splunk ingestion."""
import json
import mmap
import sys
import time
from pathlib import Path

import yara_x

RULES = Path("/Users/julientaste/testsplunk/rules/apt_detection_rules.yar")
IMAGE = Path("/Users/julientaste/Downloads/base-dc-memory/base-dc-memory.img")
OUT = Path("/Users/julientaste/testsplunk/artifacts/yara_hits.json")

def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rules = yara_x.compile(RULES.read_text())
    scanner = yara_x.Scanner(rules)

    t0 = time.time()
    with IMAGE.open("rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            results = scanner.scan(mm)
        finally:
            mm.close()
    elapsed = time.time() - t0

    hits = []
    for rule in results.matching_rules:
        meta = dict(rule.metadata)
        match_offsets = []
        total_matches = 0
        for pattern in rule.patterns:
            for m in pattern.matches:
                total_matches += 1
                if len(match_offsets) < 10:
                    match_offsets.append({
                        "pattern": pattern.identifier,
                        "offset": m.offset,
                        "length": m.length,
                    })
        hits.append({
            "rule": rule.identifier,
            "description": meta.get("description", ""),
            "severity": meta.get("severity", "unknown"),
            "mitre": meta.get("mitre", ""),
            "total_matches": total_matches,
            "sample_offsets": match_offsets,
            "image": IMAGE.name,
        })

    OUT.write_text(json.dumps({
        "scan_seconds": round(elapsed, 1),
        "image": str(IMAGE),
        "rules_file": str(RULES),
        "matching_rules": len(hits),
        "hits": hits,
    }, indent=2))
    print(f"Scan complete in {elapsed:.0f}s — {len(hits)} rules matched → {OUT}")

if __name__ == "__main__":
    sys.exit(main())
