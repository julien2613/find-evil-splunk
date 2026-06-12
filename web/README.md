# web/splunk_react — A2UI renderer (native Splunk React components)

Source of the React bundle that renders the **A2UI** output of the official Splunk agent
(`splunklib.ai`) as `@splunk/react-ui` components, in the app's **A2UI Native** view.

- A2UI generation: `splunk_app/find_evil/bin/a2ui_agent.py` (official agent) writes
  `appserver/static/forensic_report.a2ui.json` (A2UI v0.9: data model + bindings + templates).
- Rendering: `splunk_react/src/a2ui_app.jsx` → bundle `appserver/static/a2ui_react.js`.

## Build
```bash
cd splunk_react && npm install && node build.mjs
# -> ../../splunk_app/find_evil/appserver/static/a2ui_react.js
```
