# app/services/remediation_helper.py
import os
import httpx
import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

# ====== CONFIG ======
G4F_API_URL = os.getenv("G4F_API_URL", "http://g4f-service:1337/v1/chat/completions")
DEFAULT_MODEL = "openai/gpt-4o-mini"  # model cố định
FORCED_PROVIDER = "OpenRouter"  # ép chỉ dùng OpenRouter

# g4f-service có thể yêu cầu key riêng để xác thực request
G4F_API_KEY = os.getenv("G4F_API_KEY")

# Header cho g4f-service
headers = {"Content-Type": "application/json"}
if G4F_API_KEY:
    headers["g4f-api-key"] = G4F_API_KEY

# Nếu muốn log raw response, bật lên True
DEBUG_G4F_RESPONSE = os.getenv("DEBUG_G4F_RESPONSE", "false").lower() == "true"

# Fallback templates nếu AI thất bại
FALLBACK_TEMPLATES = {
    "critical": "Immediately patch or isolate affected components. Deploy emergency fixes and block exploit paths.",
    "high": "Upgrade to the fixed version or apply vendor patch. Review affected dependencies and monitor actively.",
    "medium": "Plan fix in next release cycle. Limit exposure through configuration hardening.",
    "low": "Address in maintenance cycle; document rationale if deferral is needed.",
    "unknown": "Investigate severity and verify exploitability before mitigation planning.",
}


# ====== CORE FUNCTION ======
async def _query_g4f(prompt: str) -> str:
    """
    Gọi g4f-service và ép provider = OpenRouter, model = gpt-4o-mini.
    """
    payload = {
        "model": DEFAULT_MODEL,
        "provider": FORCED_PROVIDER,  # ép provider duy nhất
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.6,
    }

    try:
        async with httpx.AsyncClient(timeout=50) as client:
            resp = await client.post(G4F_API_URL, headers=headers, json=payload)
            resp.raise_for_status()

            data = resp.json()
            if DEBUG_G4F_RESPONSE:
                log.info(f"[AI][DEBUG] Raw response: {data}")

            text = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )

            if not text:
                raise ValueError("Empty completion text returned")

            log.info(f"[AI] Response received from provider={FORCED_PROVIDER}")
            return text

    except Exception as e:
        log.warning(f"[AI] OpenRouter/g4f call failed: {e}")
        raise


# ====== PUBLIC ENTRY ======
async def generate_remediation(vuln_or_control: Dict[str, Any]) -> Dict[str, str]:
    """
    Generate concise, markdown-formatted remediation using OpenRouter (via g4f-service).
    Fallback to templates if all fail.
    """
    title = (
        vuln_or_control.get("control_title")
        or vuln_or_control.get("title")
        or vuln_or_control.get("vuln_id", "Unknown")
    )
    category = vuln_or_control.get("category") or "General"
    ctrl_id = (
        vuln_or_control.get("control_id")
        or vuln_or_control.get("component_name")
        or "N/A"
    )
    severity = (vuln_or_control.get("severity") or "medium").lower()
    score = vuln_or_control.get("score", "N/A")

    prompt = f"""
You are a cybersecurity consultant. Provide concise, actionable remediation.

Details:
- Control or Vulnerability: {title}
- Category: {category}
- Identifier: {ctrl_id}
- Severity/Score: {severity} ({score}%)

Provide markdown formatted output:
### Summary
<short risk/impact>
### Remediation Steps
1. <fix step>
2. <example or command if applicable>
3. <config or policy guidance>
"""

    try:
        text = await _query_g4f(prompt)
        return {"remediation": text, "source": FORCED_PROVIDER}
    except Exception as e:
        log.warning(f"[AI] Remediation via {FORCED_PROVIDER} failed: {e}")

    fallback = FALLBACK_TEMPLATES.get(severity, FALLBACK_TEMPLATES["unknown"])
    text = f"### Summary\nThis control requires attention in {category}.\n### Remediation Steps\n- {fallback}\n- Validate compliance and re-run assessment."
    return {"remediation": text, "source": "template"}
