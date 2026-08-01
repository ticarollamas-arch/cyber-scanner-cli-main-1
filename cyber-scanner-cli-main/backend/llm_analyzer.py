"""LLM-powered Proof of Concept & Remediation generator (Claude Sonnet 4.5)."""
import os
import json
import re
from emergentintegrations.llm.chat import LlmChat, UserMessage

EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY")


SYSTEM_PROMPT = """You are VulnScan AI — an elite offensive security engineer producing STRICT JSON reports on real code vulnerabilities.

CRITICAL RULES:
- Output ONLY a single valid JSON object matching the schema below. No prose, no markdown fences.
- Base the analysis STRICTLY on the code snippet provided. Do not hallucinate.
- PoC commands must be REAL and REPRODUCIBLE in a bash sandbox (use curl, python3, node, sh, echo).
- If the vulnerability cannot be reliably exploited in a local sandbox, mark reproducible=false and explain.

SCHEMA:
{
  "title": "Concise vulnerability title (<= 80 chars)",
  "cwe": "CWE-XX",
  "owasp": "OWASP category if applicable",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100 integer,
  "impact": "Business impact in 1-3 sentences",
  "root_cause": "Technical root cause in 2-4 sentences",
  "attack_vector": "Step-by-step attacker path (short bullets separated by \\n)",
  "poc_commands": [
    {
      "step": 1,
      "description": "What this step does",
      "command": "actual bash command to reproduce",
      "expected_output": "What should appear proving exploit"
    }
  ],
  "reproducible": true|false,
  "remediation": "Concrete code-level fix with a short before/after snippet",
  "patch_diff": "unified diff showing the fix",
  "references": ["url1", "url2"]
}
"""


async def analyze_vulnerability(finding: dict, file_content: str = "") -> dict:
    """Ask Claude Sonnet 4.5 to enrich a finding with reproducible PoC + remediation."""
    if not EMERGENT_LLM_KEY:
        return _fallback(finding)

    context_snippet = file_content[:2500] if file_content else finding.get("code_snippet", "")

    user_msg = f"""FINDING FROM SCANNER ({finding.get('scanner')}):
- Title: {finding.get('title')}
- Rule: {finding.get('rule_id')}
- Severity: {finding.get('severity')}
- CWE: {finding.get('cwe')}
- File: {finding.get('file_path')}:{finding.get('line_start')}
- Description: {finding.get('description')}

CODE SNIPPET:
```
{context_snippet}
```

Produce the strict JSON analysis now."""

    chat = LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=f"vuln-{finding.get('rule_id', 'x')}-{finding.get('file_path', 'x')[:20]}",
        system_message=SYSTEM_PROMPT,
    ).with_model("anthropic", "claude-sonnet-4-5-20250929")

    try:
        response = await chat.send_message(UserMessage(text=user_msg))
    except Exception as e:
        return _fallback(finding, error=str(e))

    text = (response or "").strip()
    # Extract JSON block
    if text.startswith("```"):
        text = re.sub(r"^```(json)?", "", text)
        text = re.sub(r"```$", "", text).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)
    try:
        data = json.loads(text)
    except Exception:
        return _fallback(finding, error="json_parse_failed", raw=text[:500])

    # Normalize
    data.setdefault("title", finding.get("title", ""))
    data.setdefault("cwe", finding.get("cwe", ""))
    data.setdefault("severity", finding.get("severity", "MEDIUM"))
    data.setdefault("poc_commands", [])
    data.setdefault("references", finding.get("references", []) or [])
    return data


def _fallback(finding: dict, error: str = "", raw: str = "") -> dict:
    """Provide a deterministic non-LLM PoC template."""
    return {
        "title": finding.get("title", "Unknown vulnerability"),
        "cwe": finding.get("cwe", ""),
        "owasp": finding.get("owasp", ""),
        "severity": finding.get("severity", "MEDIUM"),
        "confidence": 50,
        "impact": finding.get("description", "")[:300],
        "root_cause": finding.get("description", "")[:400],
        "attack_vector": "AI analysis unavailable; review manually.",
        "poc_commands": [
            {
                "step": 1,
                "description": "Inspect the vulnerable file",
                "command": f"cat -n \"{finding.get('file_path','')}\" | sed -n '{max(1, finding.get('line_start', 1)-3)},{finding.get('line_end', finding.get('line_start',1))+3}p'",
                "expected_output": "Shows the affected code lines"
            }
        ],
        "reproducible": False,
        "remediation": "See scanner references for guidance.",
        "patch_diff": "",
        "references": finding.get("references", []) or [],
        "_llm_error": error,
        "_raw": raw,
    }
