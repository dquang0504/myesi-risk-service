# app/services/risk_service.py
import os
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import RiskScore, Vulnerability
from datetime import datetime
from typing import List, Dict, Tuple
from cvss import CVSS3
import logging
from sqlalchemy import text
import httpx

log = logging.getLogger(__name__)

# --- Fallback mapping if CVSS vector missing ---
SEVERITY_MAP = {
    "none": 0.0,
    "low": 3.1,
    "medium": 6.0,
    "moderate": 6.0,
    "high": 8.5,
    "critical": 10.0,
}

# --- Likelihood weights from Attack Vector ---
LIKELIHOOD_AV = {
    "AV:N": 0.90,  # Network
    "AV:A": 0.70,  # Adjacent
    "AV:L": 0.50,  # Local
    "AV:P": 0.30,  # Physical
}

# --- Default Business Criticality (constant until data model supports it) ---
DEFAULT_BUSINESS_CRITICALITY = 1.2


def _parse_cvss(cvss_vector: str) -> Tuple[float, float]:
    """
    Parse CVSS vector and return (impact_normalized, likelihood).
    """
    if not cvss_vector:
        return 0.0, 0.0
    impact = 0.0
    likelihood = 0.0
    try:
        cvss_obj = CVSS3(cvss_vector)
        base_score = float(cvss_obj.scores()[0])
        impact = base_score / 10.0  # normalize 0..1
        vec = cvss_vector.upper()
        for k, v in LIKELIHOOD_AV.items():
            if k in vec:
                likelihood = v
                break
        if likelihood == 0.0:
            likelihood = 0.6  # default medium likelihood
    except Exception:
        pass
    return impact, likelihood


async def compute_risk_score(
    vulns: List[Vulnerability],
    prefer_max: bool = False,
) -> float:
    """
    Compute normalized risk score (0–10) for a component version.
    Formula (ISO 27001 / NIST SP 800-30 inspired):
        Risk = 10 × aggregate(Likelihood × Impact × Criticality)
    """
    if not vulns:
        return 0.0

    b_crit = DEFAULT_BUSINESS_CRITICALITY
    raw_scores: List[float] = []

    for v in vulns:
        impact, likelihood = 0.0, 0.0

        # safe coercion of fields
        vuln_id = getattr(v, "vuln_id", None) or ""
        try:
            vuln_id_str = str(vuln_id).upper()
        except Exception:
            vuln_id_str = ""

        cvss_vec = ""
        try:
            cvss_vec = (getattr(v, "cvss_vector", None) or "") or ""
        except Exception:
            cvss_vec = ""

        severity_raw = (getattr(v, "severity", None) or "") or ""
        severity_str = ""
        try:
            severity_str = str(severity_raw).lower()
        except Exception:
            severity_str = ""

        # --- Special case for malware indicators ---
        if vuln_id_str.startswith("MAL-"):
            impact, likelihood = 1.0, 0.95
            log.debug(
                "MAL detected, setting impact=1.0 likelihood=0.95 for %s", vuln_id_str
            )
        # --- Try CVSS vector parse when present and non-empty ---
        elif cvss_vec:
            try:
                impact, likelihood = _parse_cvss(cvss_vec)
                log.debug(
                    "Parsed CVSS %s -> impact=%.3f likelihood=%.3f",
                    cvss_vec,
                    impact,
                    likelihood,
                )
            except Exception as e:
                log.debug("Failed to parse CVSS '%s': %s", cvss_vec, e)
                impact, likelihood = 0.0, 0.0

        # --- Fallback: use severity mapping if impact still zero ---
        if impact == 0.0:
            if severity_str:
                mapped = SEVERITY_MAP.get(severity_str, 0.0)
                impact = mapped / 10.0  # normalize 0..1
                # set conservative likelihood if still zero
                likelihood = 0.6 if impact > 0 else 0.0
                log.debug(
                    "Fallback severity '%s' -> impact=%.3f likelihood=%.3f (mapped=%s)",
                    severity_str,
                    impact,
                    likelihood,
                    mapped,
                )
            else:
                # leave at zero (no info)
                log.debug("No CVSS or severity available for vuln (id=%s)", vuln_id_str)

        if impact > 0 and likelihood > 0:
            raw_scores.append(likelihood * impact * b_crit)
            log.debug(
                "Raw score appended: %.6f (impact=%.3f likelihood=%.3f b_crit=%.3f)",
                likelihood * impact * b_crit,
                impact,
                likelihood,
                b_crit,
            )

    if not raw_scores:
        return 0.0

    agg = max(raw_scores) if prefer_max else sum(raw_scores) / len(raw_scores)
    score = round(agg * 10.0, 2)
    return max(0.0, min(score, 10.0))


async def save_risk_scores(
    vulns: List[Vulnerability],
    sbom_id: str,
    db: AsyncSession,
    prefer_max: bool = False,
) -> List[Dict]:
    """
    Calculate per-component risk score, save to DB, and update project metrics.
    """
    if not vulns:
        return []

    # --- Group by component + version ---
    grouped: Dict[Tuple[str, str], List[Vulnerability]] = {}
    for v in vulns:
        grouped.setdefault((v.component_name, v.component_version), []).append(v)

    results: List[Dict] = []
    project_name = vulns[0].project_name

    for (name, version), vlist in grouped.items():
        score = await compute_risk_score(vlist, prefer_max=prefer_max)
        risk = RiskScore(
            sbom_id=sbom_id,
            component_name=name,
            component_version=version,
            score=score,
            created_at=datetime.utcnow(),
        )
        db.add(risk)
        results.append(
            {"component_name": name, "component_version": version, "score": score}
        )

    await db.commit()

    # --- Update project-level metrics ---
    if project_name:
        try:
            await db.execute(
                text(
                    """
                    UPDATE projects
                    SET 
                        avg_risk_score = COALESCE((
                            SELECT ROUND(AVG(r.score)::numeric, 2)
                            FROM risk_scores r
                            JOIN vulnerabilities v ON v.sbom_id = r.sbom_id
                            WHERE v.project_name = :p
                        ), 0),
                        total_vulnerabilities = COALESCE((
                            SELECT COUNT(*) FROM vulnerabilities v WHERE v.project_name = :p
                        ), 0),
                        updated_at = NOW()
                    WHERE name = :p
                """
                ),
                {"p": project_name},
            )
            await db.commit()
            log.info(
                "Updated project metrics for %s (avg_risk_score, total_vulnerabilities)",
                project_name,
            )
        except Exception as e:
            log.exception(
                "Failed to update project summary for %s: %s", project_name, e
            )

    return results


async def get_risk_trends(db: AsyncSession) -> List[Dict]:
    """Calculate average risk score for each component on every SBOMs"""
    result = await db.execute(
        text(
            """
            SELECT component_name, AVG(score) as average_score, COUNT(DISTINCT sbom_id) as sbom_count
            FROM risk_scores
            GROUP BY component_name
        """
        )
    )
    rows = result.all()
    trends: List[Dict] = [
        {"component_name": row[0], "average_score": float(row[1]), "sbom_count": row[2]}
        for row in rows
    ]
    return trends


G4F_API_URL = os.getenv("G4F_API_URL", "http://g4f-service:8080/v1/chat/completions")


async def call_g4f_remediation(prompt: str) -> str:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            G4F_API_URL,
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        # Giả sử structure giống OpenAI: {"choices":[{"message":{"content": "..."} }]}
        return data["choices"][0]["message"]["content"]
