# web/splunk_react — Renderer A2UI (composants React natifs Splunk)

Source du bundle React qui rend la sortie **A2UI** de l'agent officiel Splunk
(`splunklib.ai`) en composants `@splunk/react-ui`, dans la vue **A2UI Native** de l'app.

- Génération de l'A2UI : `splunk_app/find_evil/bin/a2ui_agent.py` (agent officiel) écrit
  `appserver/static/forensic_report.a2ui.json` (A2UI v0.9 : data model + bindings + templates).
- Rendu : `splunk_react/src/a2ui_app.jsx` → bundle `appserver/static/a2ui_react.js`.

## Build
```bash
cd splunk_react && npm install && node build.mjs
# -> ../../splunk_app/find_evil/appserver/static/a2ui_react.js
```
