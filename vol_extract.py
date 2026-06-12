#!/usr/bin/env python3
"""Volatility3 extraction from the memory image — one JSON per plugin.

Replaces the old vol_extract.sh: a 100% Python pipeline (no shell).
Runs the Volatility3 plugins and writes artifacts/<plugin>.json.

Usage:
    python vol_extract.py [path_to_image.img]
    # or: MEMORY_IMAGE=/path/to/image.img python vol_extract.py
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).parent
ARTIFACTS = BASE / "artifacts"
DEFAULT_IMAGE = "/Users/julientaste/Downloads/base-dc-memory/base-dc-memory.img"
PLUGINS = [
    "windows.pslist",
    "windows.psscan",
    "windows.cmdline",
    "windows.netscan",
    "windows.sessions",
]


def _vol_cmd():
    """Resolves the Volatility3 executable (local venv, PATH, or python module)."""
    local = BASE / ".venv" / "bin" / "vol"
    if local.exists():
        return [str(local)]
    found = shutil.which("vol")
    if found:
        return [found]
    # Fallback: python module -m volatility3
    return [sys.executable, "-m", "volatility3"]


def main():
    image = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MEMORY_IMAGE", DEFAULT_IMAGE)
    if not Path(image).exists():
        sys.exit(f"Memory image not found: {image}")
    ARTIFACTS.mkdir(exist_ok=True)
    vol = _vol_cmd()
    print(f"Volatility: {' '.join(vol)} | image: {image}")

    for plugin in PLUGINS:
        out = ARTIFACTS / f"{plugin.replace('.', '_')}.json"
        err = ARTIFACTS / f"{plugin.replace('.', '_')}.err"
        print(f"=== {plugin} → {out.name} ===", flush=True)
        with out.open("w") as fo, err.open("w") as fe:
            rc = subprocess.run(
                vol + ["-q", "-f", image, "-r", "json", plugin],
                stdout=fo, stderr=fe,
            ).returncode
        size = out.stat().st_size
        if rc == 0 and size > 4:
            print(f"  OK ({size} bytes)")
        else:
            print(f"  FAILED (rc={rc}, see {err.name}) — common on netscan (memory smear)")
    print("Extraction complete. psscan is enough for the pipeline (pslist/cmdline/netscan may fail).")


if __name__ == "__main__":
    sys.exit(main())
