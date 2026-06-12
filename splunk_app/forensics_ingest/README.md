# forensics_ingest — Technology Add-on (index + sourcetypes)

TA versionné qui définit l'**index** `forensics` et le **parsing** des sourcetypes
forensiques. L'ingestion elle-même se fait via le SDK Python officiel
(`../../ingest_to_splunk.py`, `index.attached_socket`).

## Contenu
- `default/indexes.conf` — index `forensics` (rétention 10 ans).
- `default/props.conf` — parsing JSON + extraction `_time` :
  - `INDEXED_EXTRACTIONS = json` (champs extraits à l'indexation),
  - `TIMESTAMP_FIELDS = event_time` + `TIME_FORMAT` (heure réelle de l'évidence),
  - `MAX_DAYS_AGO = 4000` (l'évidence date de 2018, au-delà du défaut),
  - `KV_MODE = none` + `AUTO_KV_JSON = false` (pas de double extraction au search-time).

## Schéma des sourcetypes

### `forensics:process` (Volatility3 windows.psscan)
| Champ | Description |
|---|---|
| `event_time` | horodatage (ISO8601) — source de `_time` |
| `pid`, `ppid` | PID / PID parent |
| `process_name` | nom du processus |
| `create_time`, `exit_time` | création / fin |
| `threads`, `session_id`, `wow64`, `offset_v` | métadonnées process |
| `image`, `host_role`, `os` | contexte de l'évidence |

### `forensics:yara_hit` (YARA-X apt_detection_rules)
| Champ | Description |
|---|---|
| `event_time` | horodatage d'acquisition — source de `_time` |
| `rule` | nom de la règle YARA |
| `severity` | critical / high / medium / low / informational |
| `mitre` | technique(s) MITRE ATT&CK |
| `description` | description de la règle |
| `image`, `host_role` | contexte |

### `forensics:incident` (workflow SOC — `| collect`)
Généré par l'alerte planifiée (verdict, comptes, analyse IA).

## Installation
Copier ce dossier dans `$SPLUNK_HOME/etc/apps/forensics_ingest/` puis redémarrer
Splunk (les réglages index-time de `props.conf` s'appliquent au démarrage).

> Évolution pro : aligner les champs sur le **CIM** (Endpoint.Processes :
> `process`, `process_id`, `parent_process_id`) pour la compatibilité Enterprise Security.
