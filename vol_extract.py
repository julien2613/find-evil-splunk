#!/usr/bin/env python3
"""Volatility3 extraction from a memory image — one JSON per plugin (artifacts/<plugin>.json).

A pure-Python pipeline (no shell): resolves the Volatility3 executable, runs each plugin
with a per-plugin timeout, and writes its JSON (stdout) and log (stderr) to artifacts/.
Consumed downstream by ingest_to_splunk.py (windows.psscan → forensics:process).

Usage:
    python vol_extract.py [--image IMG] [--timeout SECS] [--plugins P1 P2 ...]
    # or: MEMORY_IMAGE=/path/to/image.img python vol_extract.py
"""
import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

LOG = logging.getLogger("find_evil.vol")
BASE = Path(__file__).resolve().parent
DEFAULT_IMAGE = os.environ.get(
    "MEMORY_IMAGE", "/Users/julientaste/Downloads/base-dc-memory/base-dc-memory.img")
PLUGINS = ["windows.pslist", "windows.psscan", "windows.cmdline",
           "windows.netscan", "windows.sessions"]


def vol_cmd() -> list:
    """Resolve the Volatility3 executable: local venv, then PATH, then `python -m volatility3`."""
    local = BASE / ".venv" / "bin" / "vol"
    if local.exists():
        return [str(local)]
    found = shutil.which("vol")
    if found:
        return [found]
    return [sys.executable, "-m", "volatility3"]


def main():
    ap = argparse.ArgumentParser(description="Volatility3 extraction → JSON per plugin")
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--artifacts", default=str(BASE / "artifacts"))
    ap.add_argument("--timeout", type=int, default=900, help="per-plugin timeout (seconds)")
    ap.add_argument("--plugins", nargs="+", default=PLUGINS)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    image = Path(args.image)
    if not image.exists():
        sys.exit(f"Memory image not found: {image} (set --image or MEMORY_IMAGE)")
    artifacts = Path(args.artifacts)
    artifacts.mkdir(parents=True, exist_ok=True)
    vol = vol_cmd()
    LOG.info("Volatility: %s | image: %s", " ".join(vol), image)

    ok = 0
    for plugin in args.plugins:
        out = artifacts / f"{plugin.replace('.', '_')}.json"
        err = artifacts / f"{plugin.replace('.', '_')}.err"
        LOG.info("running %s → %s", plugin, out.name)
        try:
            with out.open("w") as fo, err.open("w") as fe:
                rc = subprocess.run(
                    vol + ["-q", "-f", str(image), "-r", "json", plugin],
                    stdout=fo, stderr=fe, timeout=args.timeout,
                ).returncode
        except FileNotFoundError:
            sys.exit(f"Volatility3 not found ({' '.join(vol)}). Install: pip install volatility3")
        except subprocess.TimeoutExpired:
            LOG.warning("  %s timed out after %ds (see %s)", plugin, args.timeout, err.name)
            continue
        if rc == 0 and out.stat().st_size > 4:
            ok += 1
            LOG.info("  OK (%d bytes)", out.stat().st_size)
        else:
            LOG.warning("  %s failed (rc=%s, see %s) — common on netscan (memory smear)",
                        plugin, rc, err.name)
    LOG.info("Done: %d/%d plugins OK. windows.psscan is enough for the pipeline.", ok, len(args.plugins))


if __name__ == "__main__":
    main()
