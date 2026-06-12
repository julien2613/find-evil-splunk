#!/usr/bin/env python3
"""Ingestion forensique vers Splunk — via le SDK Python officiel (splunk-sdk-python).

Connexion au service Splunk puis index.attached_socket() pour streamer les événements
JSON ; le parsing (champs + _time depuis event_time) est assuré par le TA versionné
`splunk_app/forensics_ingest` (props.conf).

Sourcetypes produits (champs alignés CIM — Common Information Model)
-------------------------------------------------------------------
forensics:process   — un processus (Volatility3 windows.psscan) — CIM Endpoint.Processes
    event_time, dest, process_name, process_id, parent_process_id, create_time,
    exit_time, threads, session_id, wow64, offset_v, image, host_role, os
forensics:yara_hit  — une détection YARA (apt_detection_rules.yar) — CIM Alerts/IDS
    event_time, dest, signature, description, severity, mitre, image, host_role

Config (CLI ou env) : --host/SPLUNK_HOST, --port/SPLUNK_PORT, --username/SPLUNK_USERNAME,
SPLUNK_PASSWORD (ou .splunk_pass), --index, --image-name, --artifacts.
Idempotence : --clean vide l'index avant d'ingérer (évite les doublons).

Prérequis : pip install splunk-sdk
"""
import argparse
import json
import logging
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from splunklib import client

LOG = logging.getLogger("find_evil.ingest")

BASE = Path(__file__).parent
# Format aligné sur props.conf (TIME_FORMAT %Y-%m-%dT%H:%M:%S%z). strftime -> offset +0000.
TS_FMT = "%Y-%m-%dT%H:%M:%S%z"
# Horodatage d'acquisition du dump (Windows Server 2016 DC, SRL-2018).
ACQUISITION_TIME = datetime(2018, 9, 6, 22, 57, 0, tzinfo=timezone.utc).strftime(TS_FMT)

RULE_META_RE = re.compile(r"rule\s+(\w+)\s*\{.*?meta:(.*?)(?:strings:|condition:)", re.S)
KV_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def parse_rule_metadata(yar_path: Path) -> dict:
    return {n: dict(KV_RE.findall(b)) for n, b in RULE_META_RE.findall(yar_path.read_text())}


def _event_time(iso: str) -> str:
    if not iso:
        return ACQUISITION_TIME
    try:
        return datetime.fromisoformat(iso).astimezone(timezone.utc).strftime(TS_FMT)
    except ValueError:
        return ACQUISITION_TIME


DEST = "base-dc"  # hôte (CIM dest) — contrôleur de domaine compromis (shieldbase.lan)


def process_events(artifacts: Path, image: str):
    """Champs alignés CIM Endpoint.Processes (process_name, process_id, parent_process_id, dest)."""
    data = json.loads((artifacts / "windows_psscan.json").read_text())
    for p in data:
        yield OrderedDict([
            ("event_time", _event_time(p.get("CreateTime"))),
            ("dest", DEST),
            ("process_name", p.get("ImageFileName")),
            ("process_id", p.get("PID")),
            ("parent_process_id", p.get("PPID")),
            ("create_time", p.get("CreateTime")), ("exit_time", p.get("ExitTime")),
            ("threads", p.get("Threads")), ("session_id", p.get("SessionId")),
            ("wow64", p.get("Wow64")), ("offset_v", p.get("Offset(V)")),
            ("image", image), ("host_role", "domain_controller"),
            ("os", "Windows Server 2016"),
        ])


def yara_events(artifacts: Path, rules_file: Path, image: str):
    """Champs alignés CIM Alerts/IDS (signature, severity, dest)."""
    metas = parse_rule_metadata(rules_file)
    for line in (artifacts / "yara_hits.ndjson").read_text().splitlines():
        for r in json.loads(line).get("rules", []):
            name = r.get("identifier")
            meta = metas.get(name, {})
            yield OrderedDict([
                ("event_time", ACQUISITION_TIME),
                ("dest", DEST),
                ("signature", name),
                ("description", meta.get("description", "")),
                ("severity", meta.get("severity", "unknown")),
                ("mitre", meta.get("mitre", "")),
                ("image", image), ("host_role", "domain_controller"),
            ])


def connect(args) -> client.Service:
    pw = os.environ.get("SPLUNK_PASSWORD")
    if not pw and (BASE / ".splunk_pass").exists():
        pw = (BASE / ".splunk_pass").read_text().strip()
    if not pw:
        sys.exit("SPLUNK_PASSWORD manquant (variable d'environnement ou .splunk_pass)")
    return client.connect(
        host=args.host, port=args.port, username=args.username, password=pw,
        scheme="https", verify=False, autologin=True,
    )


def ingest(index, sourcetype: str, source: str, events, image: str) -> int:
    n = 0
    with index.attached_socket(sourcetype=sourcetype, source=source, host=image) as sock:
        for ev in events:
            sock.send((json.dumps(ev) + "\n").encode("utf-8"))
            n += 1
    LOG.info("%s : %d événements ingérés (source=%s)", sourcetype, n, source)
    return n


def main():
    ap = argparse.ArgumentParser(description="Ingestion forensique via splunk-sdk-python")
    ap.add_argument("--host", default=os.environ.get("SPLUNK_HOST", "localhost"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("SPLUNK_PORT", "8089")))
    ap.add_argument("--username", default=os.environ.get("SPLUNK_USERNAME", "julien"))
    ap.add_argument("--index", default=os.environ.get("SPLUNK_INDEX", "forensics"))
    ap.add_argument("--image-name", default="base-dc-memory.img")
    ap.add_argument("--artifacts", default=str(BASE / "artifacts"))
    ap.add_argument("--rules", default=str(BASE / "rules/apt_detection_rules.yar"))
    ap.add_argument("--clean", action="store_true",
                    help="vide l'index avant d'ingérer (idempotence)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    artifacts = Path(args.artifacts)
    service = connect(args)
    index = service.indexes[args.index]

    if args.clean:
        before = int(index["totalEventCount"])
        index.clean(timeout=120)
        LOG.info("index '%s' vidé (%d -> 0 événements)", args.index, before)

    total = 0
    total += ingest(index, "forensics:process", "volatility3:windows.psscan",
                    process_events(artifacts, args.image_name), args.image_name)
    total += ingest(index, "forensics:yara_hit", "yara-x:apt_detection_rules",
                    yara_events(artifacts, Path(args.rules), args.image_name), args.image_name)
    LOG.info("Total : %d événements -> index %s (splunk-sdk-python)", total, args.index)


if __name__ == "__main__":
    main()
