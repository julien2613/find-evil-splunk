# Find Evil — Agentic Forensics (app Splunk)

App Splunk distribuable du projet *Find Evil*. Fournit l'expérience d'investigation
forensique directement dans Splunk Web, avec contrôles natifs.

## Vues

- **AI Investigation** (`ai_investigation`) — dashboard à contrôles natifs Splunk
  (sélecteurs d'angle d'analyse + connexion LLM, bouton Submit). Exécute la
  commande **`| ai`** du Splunk AI Toolkit sur les détections YARA et affiche
  le verdict + kill-chain MITRE + recommandations générés par le LLM.
- **Forensic Command Center** (`forensic_command_center`) — Dashboard Studio :
  verdict, détections critiques, triage par sévérité, LOLBins en mémoire,
  chronologie, table MITRE.

## Prérequis

- Index `forensics` peuplé (voir `../../ingest_to_splunk.py`).
- Pour *AI Investigation* : Splunk AI Toolkit configuré avec une connexion LLM
  nommée `claude` (voir `../../AI_TOOLKIT_SETUP.md`).

## Installation

Copier ce dossier dans `$SPLUNK_HOME/etc/apps/find_evil/` puis redémarrer Splunk
(ou recharger). Accès : `http://localhost:8000/en-US/app/find_evil/ai_investigation`.

## Packaging

```bash
cd splunk_app && tar czf find_evil.spl find_evil/   # paquet installable Splunkbase
```
