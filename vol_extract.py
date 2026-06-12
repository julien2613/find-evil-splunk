#!/usr/bin/env python3
"""Extraction Volatility3 de l'image mémoire — un JSON par plugin.

Remplace l'ancien vol_extract.sh : pipeline 100 % Python (pas de shell).
Lance les plugins Volatility3 et écrit artifacts/<plugin>.json.

Usage :
    python vol_extract.py [chemin_image.img]
    # ou : MEMORY_IMAGE=/chemin/image.img python vol_extract.py
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
    """Résout l'exécutable Volatility3 (venv local, PATH, ou module python)."""
    local = BASE / ".venv" / "bin" / "vol"
    if local.exists():
        return [str(local)]
    found = shutil.which("vol")
    if found:
        return [found]
    # Repli : module python -m volatility3
    return [sys.executable, "-m", "volatility3"]


def main():
    image = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MEMORY_IMAGE", DEFAULT_IMAGE)
    if not Path(image).exists():
        sys.exit(f"Image mémoire introuvable : {image}")
    ARTIFACTS.mkdir(exist_ok=True)
    vol = _vol_cmd()
    print(f"Volatility : {' '.join(vol)} | image : {image}")

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
            print(f"  OK ({size} octets)")
        else:
            print(f"  ÉCHEC (rc={rc}, voir {err.name}) — fréquent sur netscan (memory smear)")
    print("Extraction terminée. psscan suffit au pipeline (pslist/cmdline/netscan peuvent échouer).")


if __name__ == "__main__":
    sys.exit(main())
