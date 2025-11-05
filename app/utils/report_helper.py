from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from dateutil import parser as date_parser
from app.db import session as db_session


# ===== Helper: compute update freshness =====
def compute_update_score(vuln_records, sbom_updated_at=None, now=None):
    if now is None:
        now = datetime.now(timezone.utc)

    timestamps = []
    if sbom_updated_at:
        try:
            t = date_parser.isoparse(str(sbom_updated_at))
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            timestamps.append(t)
        except Exception:
            pass

    for v in vuln_records or []:
        osv = v.get("osv_metadata") or {}
        for entry in osv.get("vulns", []):
            mod = entry.get("modified")
            if mod:
                try:
                    t = date_parser.isoparse(mod)
                    if t.tzinfo is None:
                        t = t.replace(tzinfo=timezone.utc)
                    timestamps.append(t)
                except Exception:
                    pass

    if not timestamps:
        return 80.0

    last_update = max(timestamps)
    delta_days = (now - last_update).total_seconds() / 86400.0

    if delta_days <= 7:
        return 100.0
    elif delta_days <= 30:
        return 90.0
    elif delta_days <= 90:
        return 75.0
    elif delta_days <= 180:
        return 60.0
    elif delta_days <= 365:
        return 40.0
    return 20.0


# ===== Weighted Compliance (v4) =====
async def weighted_compliance(
    sbom_id: str,
    vuln_stats: Dict[str, int],
    avg_risk: float,
    vuln_records: List[dict],
    sbom_updated_at: Optional[datetime] = None,
    standard: str = "ISO_27001:2022",
    weight_override_id: Optional[int] = None,
    db: AsyncSession = Depends(db_session.get_db),
) -> Tuple[float, Dict]:
    """
    Calculates compliance score based on control mappings + compliance_weights.
    Version v4: uses real control_mappings, independent of max_affected.
    """
    # --- Load control mappings ---
    q = await db.execute(
        text(
            """
            SELECT cm.control_id, COUNT(*) AS affected
            FROM control_mappings cm
            WHERE cm.sbom_id = :sbom_id
            GROUP BY cm.control_id
        """
        ),
        {"sbom_id": sbom_id},
    )
    mappings = q.fetchall()
    control_counts = {r[0]: int(r[1]) for r in mappings} if mappings else {}

    # --- Load weights for the standard ---
    q = await db.execute(
        text(
            """
            SELECT scope_key, weight
            FROM compliance_weights
            WHERE standard = :standard AND applicable = TRUE
        """
        ),
        {"standard": standard},
    )
    rows = q.fetchall()
    weights = {r[0]: float(r[1]) for r in rows} if rows else {}

    detailed = {}
    total_weight = 0.0
    weighted_sum = 0.0

    if control_counts:
        # --- Compute score per control, independent of max_affected ---
        for ctrl, affected in control_counts.items():
            weight = weights.get(ctrl, 0.01)
            total_weight += weight
            # heuristic: assume full compliance = 100%, subtract fraction per vuln
            score = max(0.0, 1.0 - 0.1 * affected)  # mỗi vuln trừ 10%
            weighted_sum += score * weight
            detailed[ctrl] = round(score * 100, 2)
    else:
        # --- Fallback severity-based scoring ---
        severity_weights = {
            "critical": 0.25,
            "high": 0.25,
            "moderate": 0.15,
            "medium": 0.15,
            "low": 0.10,
            "unknown": 0.05,
        }
        for sev, count in vuln_stats.items():
            w = severity_weights.get(sev.lower(), 0.05)
            score = max(0.0, 1.0 - 0.5 * (count > 0))  # simple penalty if vuln exists
            weighted_sum += score * w
            total_weight += w
            detailed[sev] = round(score * 100, 2)

    cf = (weighted_sum / total_weight) if total_weight > 0 else 0.0
    update_score = compute_update_score(vuln_records, sbom_updated_at)

    compliance_score = round(((cf * 0.8) + (update_score / 100.0) * 0.2) * 100, 2)

    detailed_scores = {
        "by_control" if control_counts else "by_severity": detailed,
        "average_risk": round(avg_risk, 2),
        "update_score": update_score,
        "weights_used": weights,
        "sbom_last_updated": sbom_updated_at.isoformat() if sbom_updated_at else None,
    }

    return compliance_score, detailed_scores


# === Helper to extract detailed_controls from weighted_compliance with DB info ===
async def extract_detailed_controls(
    sbom_id: str, db: AsyncSession, detailed_scores_dict: dict
):
    controls = []
    by_control = detailed_scores_dict.get("by_control") or detailed_scores_dict.get(
        "by_severity"
    )
    if by_control:
        for ctrl, score in by_control.items():
            # fetch title and category from DB
            q = await db.execute(
                text(
                    """
                    SELECT title, category FROM compliance_weights 
                    WHERE standard IN ('ISO_27001:2022','NIST_SP_800_53','OWASP') 
                    AND scope_key = :ctrl LIMIT 1
                """
                ),
                {"ctrl": ctrl},
            )
            row = q.fetchone()
            title, category = ("", "")
            if row:
                title, category = row
            controls.append(
                {
                    "control_id": ctrl,
                    "control_title": title,
                    "category": category,
                    "score": score,
                }
            )
    return controls
