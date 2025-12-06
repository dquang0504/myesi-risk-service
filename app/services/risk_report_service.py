import io
from datetime import datetime
from typing import List, Tuple
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app.db import session as db_session


def _bar_chart(labels: List[str], values: List[float], title: str) -> str:
    fig, ax = plt.subplots(figsize=(6, 2.5))
    ax.bar(labels, values, color="#3b82f6")
    ax.set_title(title, fontsize=10)
    ax.grid(axis="y", linewidth=0.3)
    plt.xticks(rotation=25, fontsize=7)
    plt.yticks(fontsize=7)
    buf = io.BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format="png", dpi=120)
    plt.close(fig)
    buf.seek(0)
    import base64

    return base64.b64encode(buf.read()).decode("utf-8")


def _line_chart(dates: List[str], values: List[float], title: str) -> str:
    fig, ax = plt.subplots(figsize=(6, 2.5))
    ax.plot(dates, values, marker="o", color="#0ea5e9")
    ax.set_title(title, fontsize=10)
    ax.grid(True, linewidth=0.3)
    plt.xticks(rotation=35, fontsize=7)
    plt.yticks(fontsize=7)
    buf = io.BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format="png", dpi=120)
    plt.close(fig)
    buf.seek(0)
    import base64

    return base64.b64encode(buf.read()).decode("utf-8")


async def generate_risk_overview_report(
    db: AsyncSession = Depends(db_session.get_db),
) -> Tuple[bytes, str, str]:
    """
    Returns (content, content_type, filename).
    Falls back to HTML download if WeasyPrint deps are missing.
    """
    pdf_mode = True
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:
        pdf_mode = False
    # Metrics
    total_active = (
        await db.scalar(
            text("SELECT COUNT(*) FROM vulnerabilities WHERE is_active = TRUE")
        )
        or 0
    )
    total_fixed = (
        await db.scalar(
            text("SELECT COUNT(*) FROM vulnerabilities WHERE is_active = FALSE")
        )
        or 0
    )
    critical = (
        await db.scalar(
            text(
                """
            SELECT COUNT(*) FROM vulnerabilities
            WHERE is_active = TRUE AND LOWER(severity) = 'critical'
            """
            )
        )
        or 0
    )

    avg_risk = (
        await db.scalar(text("SELECT COALESCE(AVG(avg_risk_score),0) FROM projects"))
        or 0.0
    )

    # Severity distribution
    dist_rows = await db.execute(
        text(
            """
            SELECT LOWER(COALESCE(severity, 'unknown')) AS severity, COUNT(*)
            FROM vulnerabilities
            WHERE is_active = TRUE
            GROUP BY LOWER(COALESCE(severity, 'unknown'))
            ORDER BY 2 DESC
            """
        )
    )
    dist = dist_rows.fetchall()
    dist_labels = [r[0] for r in dist]
    dist_values = [int(r[1]) for r in dist]

    # Trend: daily active vuln count (last 14 days)
    trend_rows = await db.execute(
        text(
            """
            SELECT DATE(created_at) AS day, COUNT(*)
            FROM vulnerabilities
            WHERE is_active = TRUE
              AND created_at >= CURRENT_DATE - INTERVAL '14 days'
            GROUP BY DATE(created_at)
            ORDER BY day
            """
        )
    )
    trend = trend_rows.fetchall()
    trend_dates = [r[0].strftime("%Y-%m-%d") for r in trend]
    trend_values = [int(r[1]) for r in trend]

    # Top projects by avg risk (active vulnerabilities only)
    proj_rows = await db.execute(
        text(
            """
            SELECT p.name, COALESCE(AVG(rs.score),0) AS avg_risk, COUNT(v.id) AS active_vulns
            FROM projects p
            LEFT JOIN sboms s ON s.project_id = p.id
            LEFT JOIN vulnerabilities v
              ON v.sbom_id = s.id
             AND v.is_active = TRUE
            LEFT JOIN risk_scores rs
              ON rs.sbom_id = v.sbom_id
             AND rs.component_name = v.component_name
             AND rs.component_version = v.component_version
            GROUP BY p.name
            ORDER BY avg_risk DESC NULLS LAST
            LIMIT 10
            """
        )
    )
    projects = [(r[0], float(r[1] or 0), int(r[2] or 0)) for r in proj_rows.fetchall()]

    # Charts
    dist_chart = _bar_chart(
        dist_labels or ["none"], dist_values or [0], "Severity distribution"
    )
    trend_chart = _line_chart(
        trend_dates or ["n/a"], trend_values or [0], "Active vulnerabilities trend"
    )

    # Render HTML
    html = f"""
    <html>
      <head>
        <style>
          body {{ font-family: Arial, sans-serif; color: #0f172a; }}
          h1, h2 {{ color: #111827; }}
          table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
          th, td {{ border: 1px solid #e5e7eb; padding: 6px 8px; font-size: 12px; }}
          th {{ background: #f3f4f6; text-align: left; }}
          .stat {{ font-size: 14px; margin-bottom: 6px; }}
        </style>
      </head>
      <body>
        <h1>Risk Overview Report</h1>
        <p>Generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>

        <h2>Key Metrics</h2>
        <div class="stat">Total Active Vulnerabilities: <b>{total_active}</b></div>
        <div class="stat">Total Fixed: <b>{total_fixed}</b></div>
        <div class="stat">Critical Issues: <b>{critical}</b></div>
        <div class="stat">Average Project Risk: <b>{avg_risk:.2f}</b></div>

        <h2>Severity Distribution</h2>
        <img src="data:image/png;base64,{dist_chart}" alt="Severity Chart" />

        <h2>Active Vulnerabilities Trend (14d)</h2>
        <img src="data:image/png;base64,{trend_chart}" alt="Trend Chart" />

        <h2>Top Projects by Average Risk</h2>
        <table>
          <thead><tr><th>Project</th><th>Avg Risk (active)</th><th>Active Vulns</th></tr></thead>
          <tbody>
            {''.join([f"<tr><td>{p[0]}</td><td>{p[1]:.2f}</td><td>{p[2]}</td></tr>" for p in projects]) or '<tr><td colspan=3>No data</td></tr>'}
          </tbody>
        </table>
      </body>
    </html>
    """

    if pdf_mode:
        try:
            from weasyprint import HTML  # type: ignore

            pdf_bytes = HTML(string=html).write_pdf()
            return pdf_bytes, "application/pdf", "risk_overview.pdf"
        except Exception:
            pdf_mode = False

    # Fallback: return HTML bytes
    return html.encode("utf-8"), "text/html", "risk_overview.html"
