import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import re
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from dateutil import parser as date_parser
from app.db import session as db_session
from app.services.remediation_helper import generate_remediation


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


def compute_dev_hygiene(
    vuln_records: List[dict], code_findings: List[dict], sbom_updated_at=None, now=None
):
    """
    Lightweight hygiene score for developer view: SLA-ish penalties and freshness.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    def age_days(dt):
        if not dt:
            return 999
        try:
            t = date_parser.isoparse(str(dt))
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            return (now - t).total_seconds() / 86400.0
        except Exception:
            return 999

    # Vuln penalties by severity and age
    penalty = 0.0
    for v in vuln_records or []:
        sev = (v.get("severity") or "").lower()
        days = age_days(v.get("updated_at") or v.get("created_at"))
        if sev == "critical":
            if days > 30:
                penalty += 20
            elif days > 14:
                penalty += 10
            else:
                penalty += 5
        elif sev == "high":
            if days > 45:
                penalty += 10
            elif days > 21:
                penalty += 5
            else:
                penalty += 2
        elif sev in ("moderate", "medium"):
            if days > 60:
                penalty += 5
            elif days > 30:
                penalty += 2
        elif sev == "low":
            if days > 90:
                penalty += 1

    # Code findings penalty
    cf_penalty = max(0.0, len(code_findings or []) * 0.5)  # mỗi finding 0.5 điểm
    penalty += cf_penalty

    # Freshness: SBOM age
    sbom_age = age_days(sbom_updated_at)
    freshness = 0
    if sbom_age <= 30:
        freshness = 0
    elif sbom_age <= 60:
        freshness = 5
    elif sbom_age <= 120:
        freshness = 10
    else:
        freshness = 20
    penalty += freshness

    score = max(0.0, 100.0 - penalty)
    return round(score, 2)


# ===== Weighted Compliance (v4) =====
async def weighted_compliance(
    sbom_id: str,
    vuln_stats: Dict[str, int],
    avg_risk: float,
    vuln_records: List[dict],
    sbom_updated_at: Optional[datetime] = None,
    standard: str = "ISO_27001:2022",
    weight_override_id: Optional[int] = None,
    code_findings: Optional[List[dict]] = None,
    project_id: Optional[int] = None,
    db: AsyncSession = Depends(db_session.get_db),
) -> Tuple[float, Dict]:
    now = datetime.now(timezone.utc)
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
            JOIN vulnerabilities v
              ON v.sbom_id = cm.sbom_id
             AND v.component_name = cm.component_name
             AND v.component_version = cm.component_version
            WHERE cm.sbom_id = :sbom_id
              AND v.is_active = TRUE
            GROUP BY cm.control_id
        """
        ),
        {"sbom_id": sbom_id},
    )
    mappings = q.fetchall()
    control_counts = {r[0]: int(r[1]) for r in mappings} if mappings else {}

    # --- Load control mappings for code findings (optional) ---
    if project_id:
        q_cf = await db.execute(
            text(
                """
                SELECT control_id, COUNT(*) AS affected
                FROM code_finding_control_mappings
                WHERE project_id = :pid
                   OR (sbom_id IS NOT NULL AND sbom_id = :sbom_id)
                GROUP BY control_id
            """
            ),
            {"pid": project_id, "sbom_id": sbom_id},
        )
        cf_map = q_cf.fetchall()
        for r in cf_map or []:
            control_counts[r[0]] = control_counts.get(r[0], 0) + int(r[1])

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

    # --- Control mappings + code findings as controls by category ---
    cf_categories = {}
    for cf in code_findings or []:
        cat = cf.get("category") or "code_security"
        key = re.sub(r"[^A-Za-z0-9]+", "_", cat).upper()
        scope_key = f"CF_{key}"
        cf_categories[scope_key] = cf_categories.get(scope_key, 0) + 1

    all_controls = dict(control_counts)
    all_controls.update(cf_categories)

    control_score = 0.0
    if all_controls:
        for ctrl, affected in all_controls.items():
            weight = weights.get(ctrl, 0.05)
            total_weight += weight
            # mỗi vuln/finding trừ 10% điểm control, sàn 0
            score = max(0.0, 1.0 - 0.1 * affected)
            weighted_sum += score * weight
            detailed[ctrl] = round(score * 100, 2)
        control_score = (weighted_sum / total_weight) if total_weight > 0 else 0.0

    # --- Severity-based score (penalize theo số lượng vuln) ---
    severity_weights = {
        "critical": 0.25,
        "high": 0.25,
        "moderate": 0.15,
        "medium": 0.15,
        "low": 0.10,
        "unknown": 0.05,
    }
    severity_sum = 0.0
    severity_total = 0.0
    for sev, count in vuln_stats.items():
        w = severity_weights.get(sev.lower(), 0.05)
        severity_total += w
        # penalty theo số lượng và độ nặng (critical nặng hơn)
        penalty_per = {
            "critical": 0.4,
            "high": 0.25,
            "moderate": 0.15,
            "medium": 0.15,
            "low": 0.10,
        }.get(sev.lower(), 0.05)
        score = max(0.0, 1.0 - penalty_per * count)
        severity_sum += score * w
    severity_score = (severity_sum / severity_total) if severity_total > 0 else 1.0

    cf_list = code_findings or []
    cf_count = len(cf_list)
    code_findings_score = max(0.0, 1.0 - 0.05 * cf_count)

    update_score = compute_update_score(vuln_records, sbom_updated_at) / 100.0

    # --- Kết hợp: ưu tiên control score (nếu có), bổ sung severity + code findings + freshness ---
    base_score = control_score if control_counts else severity_score
    compliance_score = round(
        ((base_score * 0.7) + (severity_score * 0.2) + (update_score * 0.1)) * 100, 2
    )

    detailed_scores = {
        "by_control" if control_counts else "by_severity": (
            detailed if control_counts else {}
        ),
        "severity_score": round(severity_score * 100, 2),
        "code_findings_score": round(code_findings_score * 100, 2),
        "base_score": round(base_score * 100, 2),
        "average_risk": round(avg_risk, 2),
        "update_score": round(update_score * 100, 2),
        "weights_used": weights,
        "sbom_last_updated": sbom_updated_at.isoformat() if sbom_updated_at else None,
        "code_findings_count": cf_count,
    }

    dev_hygiene_score = compute_dev_hygiene(
        vuln_records, code_findings or [], sbom_updated_at=sbom_updated_at, now=now
    )

    detailed_scores["developer_hygiene_score"] = dev_hygiene_score

    return compliance_score, detailed_scores


# === Helper to extract detailed_controls from weighted_compliance with DB info ===
async def extract_detailed_controls(
    sbom_id: str, db: AsyncSession, detailed_scores_dict: dict
):
    controls = []
    by_control = detailed_scores_dict.get("by_control") or detailed_scores_dict.get(
        "by_severity"
    )

    if not by_control:
        return controls

    # === Step 1: fetch metadata for all controls ===
    meta_map = {}
    q = await db.execute(
        text(
            """
            SELECT scope_key, title, category 
            FROM compliance_weights 
            WHERE standard IN ('ISO_27001:2022','NIST_SP_800_53','OWASP')
        """
        )
    )
    rows = q.fetchall()
    for r in rows:
        meta_map[r[0]] = {"title": r[1], "category": r[2]}

    # === Step 2: build list ===
    for ctrl, score in by_control.items():
        meta = meta_map.get(ctrl, {"title": "", "category": "General"})
        controls.append(
            {
                "control_id": ctrl,
                "control_title": meta["title"],
                "category": meta["category"],
                "score": score,
            }
        )

    # === Step 3: concurrently fetch AI remediation ===
    tasks = [generate_remediation(c) for c in controls]
    ai_outputs = await asyncio.gather(*tasks)

    for i, rem in enumerate(ai_outputs):
        controls[i]["remediation"] = rem["remediation"]
        controls[i]["remediation_source"] = rem["source"]

    return controls
