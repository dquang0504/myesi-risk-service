import io
import json
import decimal
import matplotlib
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from app.db.models import ComplianceReport
from app.db import session as db_session
from app.utils.report_helper import weighted_compliance, compute_dev_hygiene
from app.services.remediation_helper import generate_remediation
from app.templates.burp_style_report import generate_burp_style_report

# ensure non-GUI backend for matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ===== Helper: Extract detailed controls with AI remediation =====
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

    # === Step 2: build control list ===
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

    # === Step 3: call AI remediation concurrently ===
    import asyncio

    tasks = [generate_remediation(c) for c in controls]
    ai_outputs = await asyncio.gather(*tasks)

    for i, rem in enumerate(ai_outputs):
        controls[i]["remediation"] = rem["remediation"]
        controls[i]["remediation_source"] = rem["source"]

    return controls


# ===== Compliance Report Generator =====
async def generate_compliance_report(
    project_name: str,
    user_id: int,
    standard: str = "ISO_27001:2022",
    weight_override_id: int = None,
    trend_weeks: int = 8,
    db: AsyncSession = Depends(db_session.get_db),
):
    """
    Generate compliance report PDF for a project.
    Handles SBOM limit reached and missing SBOM.
    """
    # ===== Step 0: No quota consumption for report generation =====
    quota_allowed = True
    note = ""

    # ===== Step 1: Get latest SBOM only if quota allowed =====
    sbom_id = None
    sbom_updated_at = None
    project_id = None
    vuln_records = []
    vuln_stats = {}
    avg_risk = 0
    detailed_scores = {}

    if quota_allowed:
        sbom_result = await db.execute(
            text(
                "SELECT id, updated_at, project_id FROM sboms WHERE project_name = :project ORDER BY created_at DESC LIMIT 1"
            ),
            {"project": project_name},
        )
        sbom = sbom_result.fetchone()
        if sbom:
            sbom_id, sbom_updated_at, project_id = sbom

    # ===== Step 2: Get vulnerabilities only if SBOM exists =====
    if sbom_id:
        vulns_result = await db.execute(
            text(
                """
                SELECT * 
                FROM vulnerabilities 
                WHERE sbom_id = :sbom_id AND is_active = TRUE
                """
            ),
            {"sbom_id": sbom_id},
        )
        vuln_rows = vulns_result.mappings().all()
        vuln_records = [dict(v) for v in vuln_rows]

        result = await db.execute(
            text(
                """
                SELECT COALESCE(severity, 'unknown'), COUNT(*) as count 
                FROM vulnerabilities 
                WHERE sbom_id = :sbom_id AND is_active = TRUE
                GROUP BY severity
                """
            ),
            {"sbom_id": sbom_id},
        )
        rows = result.fetchall()
        vuln_stats = {row[0]: row[1] for row in rows} if rows else {}

        result = await db.execute(
            text(
                "SELECT COALESCE(AVG(score), 0) as avg_score FROM risk_scores WHERE sbom_id = :sbom_id"
            ),
            {"sbom_id": sbom_id},
        )
        avg_risk = float(result.scalar() or 0)

    # ===== Step 3: If missing SBOM or no vulnerabilities, try code findings; otherwise continue =====
    code_findings = []
    # luôn lấy code findings để tính compliance bổ sung
    code_findings_res = await db.execute(
        text("SELECT * FROM code_findings WHERE project_name = :project"),
        {"project": project_name},
    )
    code_findings = code_findings_res.mappings().all()

    if not sbom_id and not code_findings:
        # Nothing to report
        raise ValueError(
            f"No SBOM or code findings available for project '{project_name}', cannot generate compliance report."
        )

    # ===== Step 4: Calculate compliance score only if SBOM exists =====
    compliance_score = 0.0
    detailed_scores = {}
    per_standard_scores = {}

    if sbom_id:
        standards = ["ISO_27001:2022", "NIST_SP_800_53", "OWASP"]
        for std in standards:
            if vuln_records:
                score, d = await weighted_compliance(
                    sbom_id=sbom_id,
                    vuln_stats=vuln_stats,
                    avg_risk=avg_risk,
                    vuln_records=vuln_records,
                    sbom_updated_at=sbom_updated_at,
                    standard=std,
                    weight_override_id=weight_override_id,
                    code_findings=code_findings,
                    project_id=project_id,
                    db=db,
                )
            else:
                score, d = 100.0, {
                    "by_severity": {},
                    "average_risk": avg_risk,
                    "update_score": 100.0,
                    "developer_hygiene_score": 100.0,
                }
            per_standard_scores[std] = score
            if std == standard:
                compliance_score = score
                detailed_scores = d
    else:
        compliance_score = 0
        detailed_scores = {
            "developer_hygiene_score": compute_dev_hygiene(
                [], code_findings or [], sbom_updated_at=None
            )
        }

    # ===== Step 5: Standards mapping =====
    def standard_level(standard, score, vuln_stats):
        if not quota_allowed:
            return "Not Available (subscription limit reached)"
        if standard.startswith("ISO_27001"):
            if score >= 85:
                return "Compliant"
            elif score >= 60:
                return "Partially"
            else:
                return "Non-Compliant"
        elif standard.startswith("NIST"):
            if score >= 75:
                return "Compliant"
            elif score >= 50:
                return "Needs Review"
            else:
                return "Non-Compliant"
        elif standard == "OWASP":
            critical = vuln_stats.get("critical", 0) if vuln_stats else 0
            if critical == 0:
                return "Compliant"
            elif critical <= 2:
                return "Partially"
            else:
                return "Needs Review"
        return "Unknown"

    standards = {
        "ISO_27001": standard_level(
            "ISO_27001",
            per_standard_scores.get("ISO_27001:2022", compliance_score),
            vuln_stats,
        ),
        "NIST_SP_800_53": standard_level(
            "NIST_SP_800_53",
            per_standard_scores.get("NIST_SP_800_53", compliance_score),
            vuln_stats,
        ),
        "OWASP": standard_level(
            "OWASP", per_standard_scores.get("OWASP", compliance_score), vuln_stats
        ),
    }

    # ===== Step 6: Build summary =====
    summary = {
        "total_components": sum(vuln_stats.values()) if vuln_stats else 0,
        "vulnerabilities": vuln_stats,
        "average_risk": avg_risk,
        "compliance_score": compliance_score,
        "per_standard_scores": per_standard_scores,
        "detailed_scores": detailed_scores,
        "note": note,  # <-- Add note about quota if any
    }

    # ===== Step 7: Trend data =====
    trend_weeks = int(trend_weeks or 8)
    trend_q = await db.execute(
        text(
            "SELECT created_at, report_data FROM compliance_reports "
            "WHERE project_name = :p AND report_type='compliance' "
            "ORDER BY created_at DESC LIMIT :n"
        ),
        {"p": project_name, "n": trend_weeks},
    )
    trend_rows = trend_q.fetchall()

    weeks = []
    scores = []
    for r in reversed(trend_rows):
        created_at = r[0]
        try:
            data = json.loads(r[1]) if r[1] else {}
        except Exception:
            data = {}

        if created_at:
            weeks.append(created_at.strftime("%Y-%m-%d"))
        else:
            weeks.append(datetime.utcnow().strftime("%Y-%m-%d"))

        score_val = float(data.get("compliance_score", 0))
        scores.append(score_val if score_val >= 0 else 0)

    weeks.append(datetime.utcnow().strftime("%Y-%m-%d"))
    scores.append(float(compliance_score))

    # ===== Step 8: Generate PDF report =====
    detailed_controls = []
    if sbom_id and detailed_scores:
        detailed_controls = await extract_detailed_controls(
            sbom_id, db, detailed_scores
        )

    pdf_path = await generate_burp_style_report(
        project_name=project_name,
        user_id=user_id,
        summary=summary,
        standards=standards,
        detailed_controls=detailed_controls,
        vuln_records=vuln_records,
        trend_data={"weeks": weeks, "scores": scores},
        db=db,
    )

    # ===== Step 9: Save report record =====
    report = ComplianceReport(
        sbom_id=sbom_id,
        project_name=project_name,
        report_type="compliance",
        report_data=json.dumps(
            summary,
            default=lambda o: float(o) if isinstance(o, decimal.Decimal) else o,
        ),
        report_url=pdf_path,
        generated_by=user_id,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return pdf_path, report


# ====== PDF Helper Section ======


def _create_trend_chart(weeks, scores):
    fig, ax = plt.subplots(figsize=(7, 2.5))
    ax.plot(weeks, scores, marker="o", linestyle="-", color="#1f77b4")
    ax.set_title("Compliance Trend", fontsize=10)
    ax.set_xlabel("Date", fontsize=8)
    ax.set_ylabel("Score (%)", fontsize=8)
    ax.set_ylim(0, 100)
    ax.grid(True, linewidth=0.3)
    plt.xticks(rotation=45, fontsize=7)
    plt.yticks(fontsize=7)
    buf = io.BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def _create_bar_chart(labels, values):
    fig, ax = plt.subplots(figsize=(6, 2))
    bars = ax.bar(labels, values, color="#ff7f0e")
    ax.set_title("Vulnerabilities by Severity", fontsize=10)
    ax.set_ylabel("Count", fontsize=8)
    ax.grid(axis="y", linewidth=0.3)
    plt.xticks(rotation=45, fontsize=7)
    plt.yticks(fontsize=7)
    for bar, value in zip(bars, values):
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + 0.5,
            str(value),
            ha="center",
            fontsize=7,
        )
    buf = io.BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def _color_for_score(score):
    if score >= 85:
        return (0.0, 0.6, 0.0)
    elif score >= 60:
        return (0.9, 0.65, 0.0)
    else:
        return (0.8, 0.0, 0.0)
