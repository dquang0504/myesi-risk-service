import json
import os
import html
from datetime import datetime
from markdown import markdown
from bs4 import BeautifulSoup
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    ListFlowable,
    ListItem,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.services.remediation_helper import generate_remediation


async def generate_burp_style_report(
    project_name,
    user_id,
    summary,
    standards,
    detailed_controls,
    vuln_records,
    trend_data=None,
    db=None,
):
    """
    Generate Burp Suite–style PDF compliance report.
    Handles SBOM limit reached or missing SBOM gracefully.
    """
    tmp_dir = os.path.join(os.getcwd(), "tmp_reports")
    os.makedirs(tmp_dir, exist_ok=True)
    pdf_path = os.path.join(
        tmp_dir,
        f"{project_name}_BurpStyleReport_{int(datetime.utcnow().timestamp())}.pdf",
    )

    # === Styles ===
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=60,
        bottomMargin=40,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="MainTitle",
            fontSize=18,
            leading=22,
            spaceAfter=10,
            alignment=1,
            textColor=colors.HexColor("#1A1A1A"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeader",
            fontSize=14,
            leading=18,
            spaceAfter=6,
            textColor=colors.HexColor("#2E4053"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="SubHeader",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#2E8B57"),
        )
    )
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=13, spaceAfter=4))
    styles.add(
        ParagraphStyle(name="CustomBullet", fontSize=9.5, leftIndent=20, leading=12)
    )

    story = []

    # === HEADER ===
    story.append(
        Paragraph(
            "MyESI Automated Compliance & Vulnerability Assessment", styles["MainTitle"]
        )
    )
    story.append(Paragraph(f"<b>Project:</b> {project_name}", styles["Body"]))
    story.append(
        Paragraph(
            f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;&nbsp;&nbsp; <b>User:</b> {user_id}",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 12))

    # === NOTE / SUBSCRIPTION LIMIT ===
    if summary.get("note"):
        story.append(
            Paragraph(
                f"<b>Note:</b> {summary['note']}",
                ParagraphStyle(
                    "note_style", textColor=colors.red, fontSize=10, spaceAfter=12
                ),
            )
        )

    # === EXECUTIVE SUMMARY ===
    story.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
    compliance_score = summary.get("compliance_score", 0)
    avg_risk = summary.get("average_risk", 0)
    total_vuln = summary.get("total_components", 0)

    story.append(
        Paragraph(f"• Compliance Score: <b>{compliance_score}%</b>", styles["Body"])
    )
    story.append(
        Paragraph(f"• Average Risk Score: <b>{avg_risk:.2f}</b>", styles["Body"])
    )
    story.append(
        Paragraph(f"• Total Vulnerabilities: <b>{total_vuln}</b>", styles["Body"])
    )
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Standards Compliance:</b>", styles["SubHeader"]))
    data = [["Standard", "Status"]] + [[k, v] for k, v in standards.items()]
    t = Table(data, colWidths=[250, 200])
    t.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(t)
    story.append(PageBreak())

    # === COMPLIANCE CONTROLS SECTION ===
    story.append(Paragraph("2. Compliance Controls Overview", styles["SectionHeader"]))
    if detailed_controls:
        for row in detailed_controls:
            ctrl_id = row.get("control_id")
            title = row.get("control_title", "")
            category = row.get("category", "")
            score = row.get("score", 0)
            story.append(Spacer(1, 6))
            story.append(
                Paragraph(
                    f"<b>{ctrl_id}</b> — {title} <i>({category})</i> — Score: <b>{score}%</b>",
                    styles["Body"],
                )
            )

            remediation = row.get("remediation", "")
            if remediation:
                html_text = markdown(remediation, extensions=["nl2br", "sane_lists"])
                soup = BeautifulSoup(html_text, "html.parser")
                bullets = [
                    Paragraph(li.get_text(), styles["CustomBullet"])
                    for li in soup.find_all("li")
                ]
                if bullets:
                    story.append(
                        ListFlowable([ListItem(b, leftIndent=20) for b in bullets])
                    )
                else:
                    story.append(Paragraph(soup.get_text(), styles["CustomBullet"]))
            story.append(Spacer(1, 8))
    else:
        story.append(
            Paragraph(
                "No compliance controls available (possibly due to SBOM limit reached).",
                styles["Body"],
            )
        )

    story.append(PageBreak())

    # === VULNERABILITY DETAILS SECTION ===
    story.append(Paragraph("3. Vulnerability Findings", styles["SectionHeader"]))
    if vuln_records:
        vuln_data = [
            ["#", "Component", "Version", "Vuln ID", "Severity", "Fix / Recommendation"]
        ]
        for idx, v in enumerate(vuln_records, start=1):
            comp = v.get("component_name", "N/A")
            ver = v.get("component_version", "N/A")
            vid = v.get("vuln_id", "-")
            sev = (v.get("severity") or "unknown").capitalize()
            fixable = v.get("fix_available")
            fix = v.get("fixed_version") or "N/A"
            if fixable:
                fix_text = f"<b>Update to:</b> {fix}"
            else:
                fix_ai = await generate_remediation(v)
                fix_text = fix_ai.get("remediation", "No remediation available.")
            sev_color = {
                "Critical": "#D9534F",
                "High": "#E67E22",
                "Medium": "#F1C40F",
                "Low": "#5bc0de",
            }.get(sev, "#999999")
            vuln_data.append(
                [
                    str(idx),
                    Paragraph(f"<b>{comp}</b>", styles["Body"]),
                    ver,
                    vid,
                    Paragraph(
                        f"<font color='{sev_color}'><b>{sev}</b></font>", styles["Body"]
                    ),
                    Paragraph(
                        fix_text,
                        ParagraphStyle(
                            name="Fix", fontSize=9, leading=12, leftIndent=5
                        ),
                    ),
                ]
            )
        table = Table(vuln_data, colWidths=[25, 95, 65, None, 55, 155])
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("WORDWRAP", (0, 0), (-1, -1), True),
                ]
            )
        )
        story.append(table)
    else:
        story.append(
            Paragraph(
                "No vulnerabilities available (SBOM missing or quota exceeded).",
                styles["Body"],
            )
        )

    # === CODE FINDINGS SECTION ===
    story.append(PageBreak())
    story.append(
        Paragraph("4. Code Findings (Static Analysis)", styles["SectionHeader"])
    )
    if db:
        from sqlalchemy import text

        q = await db.execute(
            text(
                "SELECT * FROM code_findings WHERE project_name = :p ORDER BY severity DESC, created_at DESC"
            ),
            {"p": project_name},
        )
        rows = q.mappings().all()
        if not rows:
            story.append(
                Paragraph("No code findings detected in the last scan.", styles["Body"])
            )
        else:
            for idx, f in enumerate(rows, start=1):
                story.append(Spacer(1, 8))
                title = f.get("rule_id", "Unknown")
                msg = f.get("message", "")
                sev = (f.get("severity") or "info").capitalize()
                conf = f.get("confidence", "N/A")
                file_path = f.get("file_path", "")
                code = html.escape(f.get("code_snippet", "") or "")
                refs_val = f.get("reference_links")
                if isinstance(refs_val, str):
                    try:
                        refs = json.loads(refs_val)
                    except Exception:
                        refs = []
                elif isinstance(refs_val, (list, tuple)):
                    refs = list(refs_val)
                else:
                    refs = []

                story.append(
                    Paragraph(f"<b>{idx}. {title}</b> ({sev} / {conf})", styles["Body"])
                )
                story.append(Paragraph(f"<i>{file_path}</i>", styles["CustomBullet"]))
                story.append(Paragraph(f"{msg}", styles["CustomBullet"]))
                if code:
                    story.append(
                        Paragraph(
                            f"<font color='#555555'><pre>{code}</pre></font>",
                            styles["Body"],
                        )
                    )
                for r in refs:
                    story.append(
                        Paragraph(
                            f"<font size=8 color='#2980b9'>{r}</font>",
                            styles["CustomBullet"],
                        )
                    )

                ai_out = await generate_remediation(
                    {
                        "title": title,
                        "category": f.get("category", "Code Quality"),
                        "severity": f.get("severity", "medium"),
                        "message": msg,
                    }
                )
                story.append(Paragraph("<b>Suggested Fix:</b>", styles["SubHeader"]))
                html_text = markdown(
                    ai_out["remediation"], extensions=["nl2br", "sane_lists"]
                )
                soup = BeautifulSoup(html_text, "html.parser")
                story.append(Paragraph(soup.get_text(), styles["CustomBullet"]))
                story.append(Spacer(1, 10))

    story.append(Spacer(1, 20))
    story.append(
        Paragraph(
            f"<font size=8><i>Generated by MyESI on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} — User: {user_id}</i></font>",
            styles["Body"],
        )
    )

    doc.build(story)
    return pdf_path
