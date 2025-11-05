import io
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from app.db.models import ComplianceReport
from app.db import session as db_session
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
import os
import json
import decimal
from app.utils.report_helper import weighted_compliance, extract_detailed_controls

# ensure non-GUI backend for matplotlib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ===== Compliance Report Generator =====
async def generate_compliance_report(
    project_name: str,
    user_id: int,
    standard: str = "ISO_27001:2022",
    weight_override_id: int = None,
    trend_weeks: int = 8,
    db: AsyncSession = Depends(db_session.get_db),
):
    # --- Get SBOM (latest) ---
    sbom_result = await db.execute(
        text(
            "SELECT id, updated_at FROM sboms WHERE project_name = :project ORDER BY created_at DESC LIMIT 1"
        ),
        {"project": project_name},
    )
    sbom = sbom_result.fetchone()
    if not sbom:
        raise Exception(f"No SBOM found for project {project_name}")

    sbom_id, sbom_updated_at = sbom

    # --- Get vulnerabilities ---
    vulns_result = await db.execute(
        text("SELECT * FROM vulnerabilities WHERE sbom_id = :sbom_id"),
        {"sbom_id": sbom_id},
    )
    vuln_rows = vulns_result.mappings().all()
    vuln_records = [dict(v) for v in vuln_rows]

    # --- Aggregate vuln stats by severity ---
    result = await db.execute(
        text(
            "SELECT COALESCE(severity, 'unknown'), COUNT(*) as count FROM vulnerabilities WHERE sbom_id = :sbom_id GROUP BY severity"
        ),
        {"sbom_id": sbom_id},
    )
    rows = result.fetchall()
    vuln_stats = {row[0]: row[1] for row in rows} if rows else {}

    # --- Average risk ---
    result = await db.execute(
        text(
            "SELECT COALESCE(AVG(score), 0) as avg_score FROM risk_scores WHERE sbom_id = :sbom_id"
        ),
        {"sbom_id": sbom_id},
    )
    avg_risk = float(result.scalar() or 0)

    # --- Compliance Calculation ---
    compliance_score, detailed_scores = await weighted_compliance(
        sbom_id=sbom_id,
        vuln_stats=vuln_stats,
        avg_risk=avg_risk,
        vuln_records=vuln_records,
        sbom_updated_at=sbom_updated_at,
        standard=standard,
        weight_override_id=weight_override_id,
        db=db,
    )

    # --- Standards mapping ---
    def standard_level(standard, score, vuln_stats):
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
            critical = vuln_stats.get("critical", 0)
            if critical == 0:
                return "Compliant"
            elif critical <= 2:
                return "Partially"
            else:
                return "Needs Review"
        return "Unknown"

    standards = {
        "ISO_27001": standard_level("ISO_27001", compliance_score, vuln_stats),
        "NIST_SP_800_53": standard_level(
            "NIST_SP_800_53", compliance_score, vuln_stats
        ),
        "OWASP": standard_level("OWASP", compliance_score, vuln_stats),
    }

    # --- Final summary ---
    summary = {
        "total_components": sum(vuln_stats.values()) if vuln_stats else 0,
        "vulnerabilities": vuln_stats,
        "average_risk": avg_risk,
        "compliance_score": compliance_score,
        "detailed_scores": detailed_scores,
    }

    # --- Build trend (fetch last N reports) ---
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

        # Defensive fix for NULL timestamps
        if created_at:
            weeks.append(created_at.strftime("%Y-%m-%d"))
        else:
            weeks.append(datetime.utcnow().strftime("%Y-%m-%d"))

        score_val = float(data.get("compliance_score", 0))
        scores.append(score_val if score_val >= 0 else 0)

    # Append current report point
    weeks.append(datetime.utcnow().strftime("%Y-%m-%d"))
    scores.append(float(compliance_score))

    # --- Generate PDF ---
    detailed_controls = await extract_detailed_controls(sbom_id, db, detailed_scores)
    pdf_path = _create_pdf(
        project_name,
        standards,
        summary,
        detailed_controls=detailed_controls,
        trend_weeks=weeks,
        trend_scores=scores,
        user_id=user_id,
    )

    # --- Save report record ---
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


# ===== PDF and chart helpers =====


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


def _create_pdf(
    project_name,
    standards,
    summary,
    detailed_controls=None,
    trend_weeks=None,
    trend_scores=None,
    user_id=None,
):
    tmp_dir = os.path.join(os.getcwd(), "tmp_reports")
    os.makedirs(tmp_dir, exist_ok=True)
    pdf_path = os.path.join(
        tmp_dir, f"{project_name}_compliance_{int(datetime.utcnow().timestamp())}.pdf"
    )

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    # === Header ===
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, f"Compliance Report — {project_name}")

    # === Compliance Score ===
    c.setFont("Helvetica-Bold", 11)
    compliance_score = summary.get("compliance_score", 0)
    c.drawString(50, height - 80, f"Compliance Score: {compliance_score}%")
    color = _color_for_score(compliance_score)
    c.setFillColorRGB(*color)
    c.rect(220, height - 95, 14, 14, fill=1, stroke=0)
    c.setFillColorRGB(0, 0, 0)

    # === Standards Summary ===
    y = height - 120
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Standards Compliance:")
    y -= 16
    c.setFont("Helvetica", 10)
    for std, val in standards.items():
        c.drawString(60, y, f"{std}: {val}")
        y -= 14

    # === Vulnerability Summary ===
    y -= 4
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Vulnerabilities Summary:")
    y -= 16
    c.setFont("Helvetica", 10)
    vulns = summary.get("vulnerabilities", {})
    for sev, count in vulns.items():
        c.drawString(70, y, f"{sev}: {count}")
        y -= 12

    # === Bar Chart ===
    if sum(vulns.values()) > 0:
        labels = list(vulns.keys())
        values = [vulns.get(k, 0) for k in labels]
        barbuf = _create_bar_chart(labels, values)
        bar_img = ImageReader(barbuf)
        c.drawImage(
            bar_img,
            50,
            y - 120,
            width=500,
            height=100,
            preserveAspectRatio=True,
            mask="auto",
        )
        y -= 130

    # === Trend Chart ===
    if trend_weeks and trend_scores:
        trendbuf = _create_trend_chart(trend_weeks, trend_scores)
        trend_img = ImageReader(trendbuf)
        c.drawImage(
            trend_img,
            50,
            y - 120,
            width=500,
            height=100,
            preserveAspectRatio=True,
            mask="auto",
        )
        y -= 130

    # === Detailed Scores Table ===
    if detailed_controls:
        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Detailed Control Scores:")
        y -= 18
        c.setFont("Helvetica", 9)
        # Table header
        c.drawString(60, y, "Control ID")
        c.drawString(140, y, "Title")
        c.drawString(320, y, "Category")
        c.drawString(420, y, "Score (%)")
        y -= 12
        for row in detailed_controls:
            ctrl_id = row.get("control_id")
            title = row.get("control_title", "")
            category = row.get("category", "")
            score = row.get("score", 0)
            c.drawString(60, y, f"{ctrl_id}")
            c.drawString(140, y, f"{title}")
            c.drawString(320, y, f"{category}")
            c.drawString(420, y, f"{score}")
            y -= 12
            if y < 100:
                c.showPage()
                y = height - 60

    # === Footer ===
    c.setFont("Helvetica-Oblique", 8)
    footer_text = f"{project_name} — Generated: {datetime.utcnow().isoformat()} — By User ID: {user_id if user_id else 'system'}"
    c.drawString(50, 30, footer_text)

    c.save()
    return pdf_path
