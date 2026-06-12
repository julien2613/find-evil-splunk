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

## Workflow SOC automatisé

`savedsearches.conf` définit l'alerte **Find Evil - Auto Triage Workflow** (planifiée
toutes les 30 min) : détecte les détections YARA critiques → triage IA via `| ai` →
écrit un incident (`sourcetype=forensics:incident`) affiché dans la vue **SOC Incidents**.

⚠️ La saved search doit **appartenir à un utilisateur ayant `apply_ai_commander_command`**
(rôle `mltk_admin`) pour que `| ai` s'exécute en contexte planifié :
```bash
curl -sk -u <user:pass> -X POST \
  "https://localhost:8089/servicesNS/nobody/find_evil/saved/searches/Find%20Evil%20-%20Auto%20Triage%20Workflow/acl" \
  -d owner=<user> -d sharing=app
```
