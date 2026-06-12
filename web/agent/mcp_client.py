"""Client JSON-RPC minimal pour le Splunk MCP Server officiel.

Réutilisé par les function tools ADK : chaque appel d'outil forensique
passe par le serveur MCP de Splunk (méthode tools/call sur /services/mcp).
"""
import json
import os
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Le token (audience=mcp) est lu depuis l'env, sinon depuis le fichier .mcp_token du repo.
_REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_URL = os.environ.get("SPLUNK_MCP_URL", "https://localhost:8089/services/mcp")


def _load_token() -> str:
    tok = os.environ.get("SPLUNK_MCP_TOKEN")
    if tok:
        return tok.strip()
    f = _REPO_ROOT / ".mcp_token"
    if f.exists():
        return f.read_text().strip()
    raise RuntimeError("Token MCP introuvable : exporter SPLUNK_MCP_TOKEN ou créer .mcp_token")


class SplunkMCP:
    def __init__(self):
        self._id = 0
        self._headers = {
            "Authorization": f"Bearer {_load_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

    def _rpc(self, method, params=None):
        self._id += 1
        resp = requests.post(
            MCP_URL,
            headers=self._headers,
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}},
            verify=False,
            timeout=60,
        )
        resp.raise_for_status()
        data = None
        for line in resp.text.splitlines():
            line = line[5:].strip() if line.startswith("data:") else line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
        if data is None:
            raise RuntimeError(f"Réponse MCP illisible: {resp.text[:200]}")
        if "error" in data:
            raise RuntimeError(f"Erreur MCP ({method}): {data['error']}")
        return data.get("result", {})

    def call_tool(self, name, arguments=None):
        """Appelle un outil MCP et renvoie la liste de résultats SPL."""
        result = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        for c in result.get("content", []):
            if c.get("type") == "text":
                try:
                    return json.loads(c["text"]).get("results", [])
                except json.JSONDecodeError:
                    return [{"text": c["text"]}]
        return []
