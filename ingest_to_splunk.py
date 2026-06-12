#!/usr/bin/env python3
"""Ingestion des artefacts forensiques vers Splunk via HEC.

Sources :
- artifacts/windows_psscan.json  -> sourcetype forensics:process
- artifacts/yara_hits.ndjson     -> sourcetype forensics:yara_hit
  (métadonnées severity/mitre/description re-parsées depuis le fichier .yar)
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = Path(__file__).parent
HEC_URL = "https://localhost:8088/services/collector/event"
HEC_TOKEN = (BASE / ".hec_token").read_text().strip()
INDEX = "forensics"
IMAGE = "base-dc-memory.img"
# Horodatage d'acquisition du dump (Windows Server 2016 DC, SRL-2018)
ACQUISITION_TIME = datetime(2018, 9, 6, 22, 57, 0, tzinfo=timezone.utc).timestamp()

RULE_META_RE = re.compile(
    r"rule\s+(\w+)\s*\{.*?meta:(.*?)(?:strings:|condition:)", re.S
)
KV_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def parse_rule_metadata(yar_path: Path) -> dict:
    metas = {}
    for name, block in RULE_META_RE.findall(yar_path.read_text()):
        metas[name] = dict(KV_RE.findall(block))
    return metas


def iso_to_epoch(s):
    if not s:
        return None
    return datetime.fromisoformat(s).timestamp()


def process_events():
    data = json.loads((BASE / "artifacts/windows_psscan.json").read_text())
    for p in data:
        t = iso_to_epoch(p.get("CreateTime")) or ACQUISITION_TIME
        yield {
            "time": t,
            "sourcetype": "forensics:process",
            "source": "volatility3:windows.psscan",
            "index": INDEX,
            "event": {
                "pid": p.get("PID"),
                "ppid": p.get("PPID"),
                "process_name": p.get("ImageFileName"),
                "create_time": p.get("CreateTime"),
                "exit_time": p.get("ExitTime"),
                "threads": p.get("Threads"),
                "session_id": p.get("SessionId"),
                "wow64": p.get("Wow64"),
                "offset_v": p.get("Offset(V)"),
                "image": IMAGE,
                "host_role": "domain_controller",
                "os": "Windows Server 2016",
            },
        }


def yara_events():
    metas = parse_rule_metadata(BASE / "rules/apt_detection_rules.yar")
    for line in (BASE / "artifacts/yara_hits.ndjson").read_text().splitlines():
        d = json.loads(line)
        for r in d.get("rules", []):
            name = r.get("identifier")
            meta = metas.get(name, {})
            yield {
                "time": ACQUISITION_TIME,
                "sourcetype": "forensics:yara_hit",
                "source": "yara-x:apt_detection_rules",
                "index": INDEX,
                "event": {
                    "rule": name,
                    "description": meta.get("description", ""),
                    "severity": meta.get("severity", "unknown"),
                    "mitre": meta.get("mitre", ""),
                    "image": IMAGE,
                    "host_role": "domain_controller",
                },
            }


def send_batch(events):
    payload = "\n".join(json.dumps(e) for e in events)
    resp = requests.post(
        HEC_URL,
        headers={"Authorization": f"Splunk {HEC_TOKEN}"},
        data=payload,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("code") != 0:
        raise RuntimeError(f"HEC a refusé le batch : {body}")


def main():
    counts = {}
    for label, gen in [("process", process_events()), ("yara_hit", yara_events())]:
        batch, n = [], 0
        for ev in gen:
            batch.append(ev)
            n += 1
            if len(batch) >= 200:
                send_batch(batch)
                batch = []
        if batch:
            send_batch(batch)
        counts[label] = n
        print(f"{label}: {n} événements envoyés")
    print(f"Total: {sum(counts.values())} événements → index {INDEX}")


if __name__ == "__main__":
    sys.exit(main())
