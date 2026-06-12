"""Native Splunk forensic agent (splunklib.ai) — deployed inside the find_evil app.

The SDK is vendored in find_evil/lib/; importing it first lets locate_app() resolve
the app-id 'find_evil' and the agent auto-discovers the Splunk MCP Server tools.

Run:
    SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
      python /Applications/Splunk/etc/apps/find_evil/bin/forensic_agent_sdk.py "question"
"""
import os
import sys

# Vendoring: the app lib must take precedence so locate_app() finds find_evil.
_LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
sys.path.insert(0, os.path.abspath(_LIB))

import asyncio
from pathlib import Path

from splunklib.client import connect
from splunklib.ai import Agent, AnthropicModel
from splunklib.ai.messages import HumanMessage
from splunklib.ai.tool_settings import ToolSettings, RemoteToolSettings, ToolAllowlist

REPO = Path("/Users/julientaste/testsplunk")

FORENSIC_TOOLS = [
    "forensics_find_attack_techniques",
    "forensics_triage_summary",
    "forensics_investigate_process",
    "forensics_attack_timeline",
    "forensics_ai_triage",
]

SYSTEM_PROMPT = """You are a senior incident-response forensic analyst.
You investigate a memory image of a Windows Server 2016 domain controller
(SRL-2018 scenario) through your tools, which query Splunk.
Start with triage and attack techniques, pivot to suspicious processes, and
reconstruct the timeline. Conclude with a verdict (COMPROMISED/SUSPICIOUS/CLEAN), the
MITRE ATT&CK kill-chain and recommendations. Answer in English, concise, cite the T-codes."""


def _secret(env_name, file_name):
    v = os.environ.get(env_name)
    if v:
        return v.strip()
    f = REPO / file_name
    return f.read_text().strip() if f.exists() else None


async def main():
    question = sys.argv[1] if len(sys.argv) > 1 else "Is this domain controller compromised?"
    anthropic_key = _secret("ANTHROPIC_API_KEY", ".anthropic_key")
    splunk_pass = _secret("SPLUNK_PASSWORD", ".splunk_pass")
    if not anthropic_key or not splunk_pass:
        sys.exit("Missing ANTHROPIC_API_KEY or SPLUNK_PASSWORD")

    service = connect(
        scheme="https", host="localhost", port=8089,
        username=os.environ.get("SPLUNK_USERNAME", "julien"),
        password=splunk_pass, autologin=True, verify=False,
    )
    model = AnthropicModel(
        model=os.environ.get("FORENSIC_SDK_MODEL", "claude-sonnet-4-6"),
        api_key=anthropic_key, base_url="https://api.anthropic.com",
    )
    async with Agent(
        model=model, service=service, system_prompt=SYSTEM_PROMPT,
        tool_settings=ToolSettings(
            local=None,
            remote=RemoteToolSettings(allowlist=ToolAllowlist(names=FORENSIC_TOOLS)),
        ),
    ) as agent:
        print(f"[Agent Splunk SDK] {question}\n")
        try:
            print("Discovered tools:", [t.name for t in agent._tools])
        except Exception:
            pass
        result = await agent.invoke([HumanMessage(content=question)])
        print("\n" + result.final_message.content)


if __name__ == "__main__":
    asyncio.run(main())
