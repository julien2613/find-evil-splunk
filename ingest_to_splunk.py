#!/usr/bin/env python3
"""Ingestion des artefacts forensiques via le SDK Python officiel Splunk.

Utilise splunklib.client (splunk-sdk-python) — connexion au service Splunk puis
index.submit() pour chaque événement, plutôt que des appels HTTP bruts au HEC.

Sources :
- artifacts/windows_psscan.json  -> sourcetype forensics:process
- artifacts/yara_hits.ndjson     -> sourcetype forensics:yara_hit

Prérequis : pip install splunk-sdk
Auth      : SPLUNK_USERNAME (def. julien) + SPLUNK_PASSWORD (env ou .splunk_pass)
"""
import json
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from splunklib import client

BASE = Path(__file__).parent
INDEX = "forensics"
IMAGE = "base-dc-memory.img"
# Format d'horodatage aligné sur props.conf (TIME_FORMAT %Y-%m-%dT%H:%M:%S%z).
# strftime produit un offset sans deux-points (+0000), que Splunk %z sait parser.
TS_FMT = "%Y-%m-%dT%H:%M:%S%z"
ACQUISITION_DT = datetime(2018, 9, 6, 22, 57, 0, tzinfo=timezone.utc)
ACQUISITION_TIME = ACQUISITION_DT.strftime(TS_FMT)

RULE_META_RE = re.compile(r"rule\s+(\w+)\s*\{.*?meta:(.*?)(?:strings:|condition:)", re.S)
KV_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def parse_rule_metadata(yar_path: Path) -> dict:
    metas = {}
    for name, block in RULE_META_RE.findall(yar_path.read_text()):
        metas[name] = dict(KV_RE.findall(block))
    return metas


def _event_time(iso):
    """Normalise un ISO8601 vers le format props.conf (ou heure d'acquisition)."""
    if not iso:
        return ACQUISITION_TIME
    try:
        return datetime.fromisoformat(iso).astimezone(timezone.utc).strftime(TS_FMT)
    except ValueError:
        return ACQUISITION_TIME


def process_events():
    data = json.loads((BASE / "artifacts/windows_psscan.json").read_text())
    for p in data:
        # event_time en 1er champ : Splunk extrait _time de l'horodatage ISO en tête.
        yield OrderedDict([
            ("event_time", _event_time(p.get("CreateTime"))),
            ("pid", p.get("PID")),
            ("ppid", p.get("PPID")),
            ("process_name", p.get("ImageFileName")),
            ("create_time", p.get("CreateTime")),
            ("exit_time", p.get("ExitTime")),
            ("threads", p.get("Threads")),
            ("session_id", p.get("SessionId")),
            ("wow64", p.get("Wow64")),
            ("offset_v", p.get("Offset(V)")),
            ("image", IMAGE),
            ("host_role", "domain_controller"),
            ("os", "Windows Server 2016"),
        ])


def yara_events():
    metas = parse_rule_metadata(BASE / "rules/apt_detection_rules.yar")
    for line in (BASE / "artifacts/yara_hits.ndjson").read_text().splitlines():
        d = json.loads(line)
        for r in d.get("rules", []):
            name = r.get("identifier")
            meta = metas.get(name, {})
            yield OrderedDict([
                ("event_time", ACQUISITION_TIME),
                ("rule", name),
                ("description", meta.get("description", "")),
                ("severity", meta.get("severity", "unknown")),
                ("mitre", meta.get("mitre", "")),
                ("image", IMAGE),
                ("host_role", "domain_controller"),
            ])


def main():
    pw = os.environ.get("SPLUNK_PASSWORD")
    if not pw and (BASE / ".splunk_pass").exists():
        pw = (BASE / ".splunk_pass").read_text().strip()
    if not pw:
        sys.exit("SPLUNK_PASSWORD manquant (env ou .splunk_pass)")

    service = client.connect(
        host=os.environ.get("SPLUNK_HOST", "localhost"),
        port=int(os.environ.get("SPLUNK_PORT", "8089")),
        username=os.environ.get("SPLUNK_USERNAME", "julien"),
        password=pw,
        scheme="https",
        verify=False,
        autologin=True,
    )
    index = service.indexes[INDEX]

    sources = {
        "forensics:process": ("volatility3:windows.psscan", process_events()),
        "forensics:yara_hit": ("yara-x:apt_detection_rules", yara_events()),
    }
    total = 0
    for sourcetype, (source, gen) in sources.items():
        n = 0
        # attach() ouvre un flux unique vers le receiver -> ingestion efficace.
        with index.attached_socket(sourcetype=sourcetype, source=source,
                                   host=IMAGE) as sock:
            for ev in gen:
                sock.send((json.dumps(ev) + "\n").encode("utf-8"))
                n += 1
        print(f"{sourcetype}: {n} événements soumis via le SDK")
        total += n
    print(f"Total: {total} événements → index {INDEX} (splunk-sdk-python)")


if __name__ == "__main__":
    sys.exit(main())
