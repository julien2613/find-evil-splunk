# Forensic evidence — `artifacts/`

Raw extraction outputs and the incident report produced from the memory image
`base-dc-memory.img` (Windows Server 2016 domain controller, SRL-2018 scenario).
Committed as **proof** of the actual forensic run. These files feed
[`../ingest_to_splunk.py`](../ingest_to_splunk.py) → the `forensics` index.

| File | Produced by | What it proves |
|---|---|---|
| `yara_hits.ndjson` | [`../yara_scan.py`](../yara_scan.py) (YARA-X, 15 rules) | The 15 signatures matched against the image — the detection ground truth |
| `windows_psscan.json` | [`../vol_extract.py`](../vol_extract.py) (Volatility3 `windows.psscan`) | Processes carved from the memory image (source of the 122 processes) |
| `windows_pslist.json`, `windows_netscan.json`, `windows_cmdline.json`, `windows_sessions.json` | Volatility3 plugins | Other plugin runs. Some are empty (`[]`) for this image — see the matching `.err` |
| `*.err` | Volatility3 / YARA-X stderr | Run logs (framework version, page-fault warnings) — provenance of the extraction |
| `incident_findings.json` | aggregation | Structured findings (techniques, severities, MITRE) |
| `incident_report.md` | report generator | Human-readable incident report (verdict, kill-chain) |

> Provenance is intentionally preserved (including the original scan path in
> `yara_hits.ndjson`). The memory image itself (`*.img`) is **not** committed.
