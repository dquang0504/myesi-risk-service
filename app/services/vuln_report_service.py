import os
import json
import io
import base64
from datetime import datetime
from typing import  Dict
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from jinja2 import Environment, FileSystemLoader, select_autoescape
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from weasyprint import HTML

from app.db import session as db_session


# === Helper ===
def _color_for_severity(sev: str) -> str:
    sev = (sev or "").lower()
    return {
        "critical": "#d7191c",
        "high": "#e6550d",
        "medium": "#fdae6b",
        "low": "#fee6ce",
        "info": "#9ecae1",
    }.get(sev, "#cccccc")


def _render_chart(sev_counts: Dict[str, int]) -> str:
    labels = list(sev_counts.keys())
    values = [sev_counts[k] for k in labels]
    colors = [_color_for_severity(k) for k in labels]

    fig, ax = plt.subplots(figsize=(5, 2))
    ax.bar(labels, values, color=colors)
    ax.set_title("Vulnerabilities by Severity", fontsize=9)
    ax.set_ylabel("Count", fontsize=8)
    plt.xticks(rotation=0, fontsize=7)
    plt.yticks(fontsize=7)
    plt.grid(axis="y", linewidth=0.3)
    buf = io.BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format="png", dpi=120)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


# === Main generator ===
async def generate_vulnerability_report(
    project_name: str,
    user_id: int,
    db: AsyncSession = Depends(db_session.get_db),
) -> str:
    # --- Fetch vulnerabilities for latest SBOM ---
    sbom_q = await db.execute(
        text(
            "SELECT id FROM sboms WHERE project_name=:p ORDER BY created_at DESC LIMIT 1"
        ),
        {"p": project_name},
    )
    sbom = sbom_q.fetchone()
    if not sbom:
        raise Exception(f"No SBOM found for {project_name}")
    sbom_id = sbom[0]

    vulns_q = await db.execute(
        text(
            """
            SELECT v.*, r.score AS risk_score
            FROM vulnerabilities v
            LEFT JOIN risk_scores r
                ON v.sbom_id = r.sbom_id
                AND v.component_name = r.component_name
                AND v.component_version = r.component_version
            WHERE v.sbom_id=:sid
            ORDER BY v.severity DESC
        """
        ),
        {"sid": sbom_id},
    )
    rows = vulns_q.mappings().all()
    vulnerabilities = [dict(r) for r in rows]

    if not vulnerabilities:
        raise Exception(f"No vulnerabilities for {project_name}")

    # --- Aggregate severity stats ---
    sev_counts = {}
    for v in vulnerabilities:
        sev = (v.get("severity") or "unknown").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # --- Risk summary ---
    avg_risk = sum([float(v.get("risk_score") or 0) for v in vulnerabilities]) / len(
        vulnerabilities
    )

    # --- Create chart ---
    chart_b64 = _render_chart(sev_counts)

    # --- Prepare issues for report ---
    issues = []
    for v in vulnerabilities:
        osv = v.get("osv_metadata") or {}
        if isinstance(osv, str):
            try:
                osv = json.loads(osv)
            except Exception:
                osv = {}

        issues.append(
            {
                "title": osv.get("summary", v.get("vuln_id", "Unknown Vulnerability")),
                "severity": (v.get("severity") or "unknown").capitalize(),
                "component": v.get("component_name"),
                "version": v.get("component_version"),
                "description": osv.get("details", "No description available."),
                "references": osv.get("references", []),
                "fix": osv.get("fixed", v.get("fixed_version") or "Not available"),
                "cvss": v.get("cvss_vector"),
                "risk_score": v.get("risk_score"),
            }
        )

    # --- Jinja2 render ---
    env = Environment(
        loader=FileSystemLoader("app/templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("vuln_report_template.html")

    html_out = template.render(
        project_name=project_name,
        user_id=user_id,
        generated=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        total_vulns=len(vulnerabilities),
        avg_risk=round(avg_risk, 2),
        sev_counts=sev_counts,
        chart_b64=chart_b64,
        issues=issues,
    )

    # --- Save HTML & PDF ---
    out_dir = os.path.join(os.getcwd(), "tmp_reports")
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, f"{project_name}_vuln_report.html")
    pdf_path = html_path.replace(".html", ".pdf")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_out)

    HTML(string=html_out).write_pdf(pdf_path)

    return pdf_path
