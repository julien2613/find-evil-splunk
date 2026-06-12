# Find Evil — Frontend agentique (CopilotKit + ADK + AG-UI)

Interface web où un **agent Claude** investigue l'image mémoire du contrôleur de
domaine en interrogeant Splunk via le **Splunk MCP Server**, et rend ses
découvertes en **UI générative** (cartes de sévérité, table MITRE, timeline).

```
Frontend Next.js + CopilotKit  ──AG-UI(SSE)──►  Agent ADK (FastAPI, :8800)
  useRenderToolCall → composants            │   LlmAgent (Claude via LiteLLM)
  forensiques (:3000)                       │   function tools
                                            └──► Splunk MCP Server (:8089/services/mcp)
                                                  → outils forensiques → index forensics
```

## Pourquoi cette couche

L'agent CLI (`../agent_investigate.py`) prouvait la boucle. Ce frontend la rend
**interactive et démontrable** : l'analyste discute en langage naturel, l'agent
choisit et enchaîne les outils MCP, et chaque résultat s'affiche en composant
React dédié plutôt qu'en texte brut. Cela répond au critère « Design » du jury et
ouvre la piste **Platform & Developer Experience**.

## Composants

| Élément | Fichier |
|---|---|
| Agent ADK + function tools (→ Splunk MCP) | [agent/agent.py](agent/agent.py) |
| Client JSON-RPC Splunk MCP | [agent/mcp_client.py](agent/mcp_client.py) |
| Endpoint runtime CopilotKit → agent | [frontend/app/api/copilotkit/route.ts](frontend/app/api/copilotkit/route.ts) |
| Composants d'UI générative (useRenderToolCall) | [frontend/components/ForensicRenderers.tsx](frontend/components/ForensicRenderers.tsx) |
| Page + sidebar de chat | [frontend/app/page.tsx](frontend/app/page.tsx) |

## Lancement

```bash
# Prérequis : Splunk + MCP Server actifs, ../setup.sh joué, .mcp_token présent
export ANTHROPIC_API_KEY=sk-ant-...
./run.sh
# → UI    http://localhost:3000
# → Agent http://localhost:8800
```

Puis dans la sidebar : **« Ce contrôleur de domaine est-il compromis ? »**
L'agent appelle `triage_summary`, `find_attack_techniques`, `investigate_process`,
`attack_timeline` — chacun rendu en composant forensique.

## Modèle LLM

Claude via LiteLLM (`anthropic/claude-sonnet-4-6` par défaut). Changer via
`FORENSIC_AGENT_MODEL`. Tout modèle LiteLLM (OpenAI, Vertex, Ollama…) fonctionne.

## A2UI (variante)

CopilotKit 1.59 embarque `@ag-ui/a2ui-middleware`. Pour activer l'UI générative
déclarative **A2UI** (au lieu des renderers React explicites), ajouter `a2ui: {}`
à la config `CopilotRuntime` et faire émettre des composants A2UI par l'agent.
Cette branche utilise `useRenderToolCall` (stable) pour la fiabilité de la démo.
