"""A2UI × Agentic Splunk SDK integration.

The official `splunklib.ai` agent investigates the memory image through the Splunk
MCP Server tools, then **structures its verdict** (pydantic output_schema). We convert
that structured output to the **A2UI** format (https://a2ui.org) and write it to the
app static dir, where the native React view (a2ui_native) renders it as
@splunk/react-ui controls.

Pipeline: Agent SDK (MCP tools) -> structured_output -> A2UI JSONL -> Splunk React render.

Run:
    SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
      python /Applications/Splunk/etc/apps/find_evil/bin/a2ui_agent.py
"""
import os
import sys

_LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
sys.path.insert(0, os.path.abspath(_LIB))

import asyncio
import json
from pathlib import Path
from typing import List, Literal

from pydantic import BaseModel, Field

from splunklib.client import connect
from splunklib.ai import Agent, AnthropicModel
from splunklib.ai.messages import HumanMessage
from splunklib.ai.tool_settings import ToolSettings, RemoteToolSettings, ToolAllowlist

import a2ui_catalog as cat

REPO = Path("/Users/julientaste/testsplunk")
STATIC = Path("/Applications/Splunk/etc/apps/find_evil/appserver/static/forensic_report.a2ui.json")
VERSION, SURFACE = "v0.9", "forensic"

# Tools without a row_limit parameter (Anthropic strict mode rejects the integer
# min/max constraints that the MCP Server row_limiter would inject).
FORENSIC_TOOLS = [
    "forensics_find_attack_techniques", "forensics_triage_summary",
]


# --- Agent structured output schema ---
class Technique(BaseModel):
    signature: str = Field(description="Detected YARA signature name (CIM)")
    severity: Literal["critical", "high", "medium", "low", "informational"]
    mitre: str = Field(description="MITRE ATT&CK identifier(s), e.g. T1003.003")
    description: str = Field(description="Short description of the technique")


class ForensicReport(BaseModel):
    verdict: Literal["COMPROMISED", "SUSPICIOUS", "CLEAN"]
    techniques: List[Technique] = Field(description="Detected attack techniques, sorted by severity")
    analysis: str = Field(description="Analyst summary in Markdown: kill-chain and reasoning")
    recommendations: List[str] = Field(description="3 to 5 prioritized remediation actions")


SYSTEM_PROMPT = """You are a senior forensic analyst. You MUST first call your tools
(at least forensics_find_attack_techniques AND forensics_triage_summary) to collect the
detections — NEVER emit a conclusion before you have the tool results. Then return a
structured report: verdict, MITRE techniques (all of those returned by the tool), Markdown
analysis, and recommendations. Base everything ONLY on the tool results. Write in English."""


def _secret(env, fname):
    v = os.environ.get(env)
    if v:
        return v.strip()
    f = REPO / fname
    return f.read_text().strip() if f.exists() else None


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def to_a2ui(report: ForensicReport) -> str:
    """Convert the agent's structured output to enriched A2UI (shared a2ui_catalog):
    the renderer maps it to dense @splunk/react-ui controls (VerdictBadge, KpiRow,
    SeverityBar, TechniqueTable, RecommendationList)."""
    techs = [{"signature": t.signature, "severity": t.severity, "mitre": t.mitre,
              "description": t.description}
             for t in sorted(report.techniques, key=lambda t: SEV_RANK.get(t.severity, 5))]
    crit = sum(1 for t in techs if t["severity"] == "critical")
    high = sum(1 for t in techs if t["severity"] == "high")
    summary = (f"{crit} critical detections, {high} high — {len(techs)} MITRE techniques "
               f"reconstructing the kill-chain on the domain controller.")
    return cat.build_forensic(SURFACE, verdict=report.verdict, summary=summary,
                              analysis=report.analysis, techniques=techs,
                              recommendations=list(report.recommendations))


async def main():
    anthropic_key = _secret("ANTHROPIC_API_KEY", ".anthropic_key")
    splunk_pass = _secret("SPLUNK_PASSWORD", ".splunk_pass")
    if not anthropic_key or not splunk_pass:
        sys.exit("Missing ANTHROPIC_API_KEY or SPLUNK_PASSWORD")

    service = connect(scheme="https", host="localhost", port=8089,
                      username=os.environ.get("SPLUNK_USERNAME", "julien"),
                      password=splunk_pass, autologin=True, verify=False)
    model = AnthropicModel(model=os.environ.get("FORENSIC_SDK_MODEL", "claude-sonnet-4-6"),
                           api_key=anthropic_key, base_url="https://api.anthropic.com")

    async with Agent(
        model=model, service=service, system_prompt=SYSTEM_PROMPT,
        output_schema=ForensicReport,
        tool_settings=ToolSettings(local=None,
            remote=RemoteToolSettings(allowlist=ToolAllowlist(names=FORENSIC_TOOLS))),
    ) as agent:
        print("[A2UI × Splunk SDK] investigation in progress…")
        result = await agent.invoke([HumanMessage(
            content="First call forensics_find_attack_techniques and forensics_triage_summary, "
                    "then produce the structured incident report from their results.")])
        report: ForensicReport = result.structured_output
        print(f"  verdict={report.verdict} | {len(report.techniques)} techniques | "
              f"{len(report.recommendations)} recommendations")
        a2ui = to_a2ui(report)
        STATIC.write_text(a2ui)
        print(f"  A2UI written ({len(a2ui)} bytes) -> {STATIC}")
        print("  Render: http://localhost:8000/en-US/app/find_evil/a2ui_native")


if __name__ == "__main__":
    asyncio.run(main())
