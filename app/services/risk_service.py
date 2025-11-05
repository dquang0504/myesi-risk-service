from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import RiskScore, Vulnerability
from datetime import datetime
from typing import List, Dict
from cvss import CVSS3

# --- Mapping fallback if cvss vector isn't present ---
SEVERITY_MAP = {
    "none": 0.0,
    "low": 3.1,
    "medium": 6.0,
    "moderate": 6.0,  # thêm alias
    "high": 8.5,
    "critical": 10.0,
}


async def compute_risk_score(
    vulns: List[Vulnerability], criticality: float = 1.0
) -> float:
    """
    Calculate weighted risk score = CVSS × exploitability × business criticality
    Exploitability derived from Attack Vector (AV) in CVSS vector.
    """
    if not vulns:
        return 0.0
    total = 0.0
    count = 0

    for v in vulns:
        cvss_score = 0.0
        exploitability = 1.0  # neutral weight

        # --- Special case for MAL- prefixed threats ---
        if v.vuln_id and str(v.vuln_id).startswith("MAL-"):
            cvss_score = 10.0
            exploitability = 1.2  # slightly boost malicious markers

        # --- Parse CVSS vector if present ---
        elif v.cvss_vector:
            try:

                cvss_obj = CVSS3(v.cvss_vector)
                base_score = cvss_obj.scores()[0]  # base score

                # Extract Attack Vector (AV) = N / A / L / P
                vector = v.cvss_vector.upper()
                if "AV:N" in vector:
                    exploitability = 1.20  # Network
                elif "AV:A" in vector:
                    exploitability = 1.10  # Adjacent
                elif "AV:L" in vector:
                    exploitability = 0.90  # Local
                elif "AV:P" in vector:
                    exploitability = 0.80  # Physical

                cvss_score = base_score

            except Exception:
                pass  # fallback severity will handle

        # --- Fallback if no CVSS vector ---
        if cvss_score == 0.0 and v.severity:
            sev = str(v.severity).lower()
            cvss_score = SEVERITY_MAP.get(sev, 0.0)

        if cvss_score > 0.0:
            weighted = cvss_score * exploitability * criticality
            total += weighted
            count += 1

    return round(total / count, 2) if count > 0 else 0.0


async def save_risk_scores(vulns: List[Vulnerability], sbom_id: str, db: AsyncSession):
    """Calculate risk score for each component and save to DB"""
    # Group by component_name + version
    grouped = {}
    for v in vulns:
        key = (v.component_name, v.component_version)
        grouped.setdefault(key, []).append(v)

    results = []
    for (name, version), vlist in grouped.items():
        score = await compute_risk_score(vlist)
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
    return results


async def get_risk_trends(db: AsyncSession) -> List[Dict]:
    """Calculate average risk score for each component on every SBOMs"""
    result = await db.execute(
        """
        SELECT component_name, AVG(score) as average_score, COUNT(DISTINCT sbom_id) as sbom_count
        FROM risk_scores
        GROUP BY component_name
        """
    )
    rows = result.all()
    trends: List[Dict] = [
        {"component_name": row[0], "average_score": float(row[1]), "sbom_count": row[2]}
        for row in rows
    ]
    return trends
