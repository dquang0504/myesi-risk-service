import asyncio
from datetime import datetime, timedelta
import logging
from typing import Any, Dict, List

from sqlalchemy import text

from app.db.session import AsyncSessionLocal
from app.utils.notifier import publish_event

logger = logging.getLogger("weekly_reports")


async def start_weekly_report_scheduler():
    """
    Background loop that waits until the next Monday 07:00 UTC and then emits
    weekly security summaries for every organization that enabled the toggle.
    """
    while True:
        delay = seconds_until_next_monday()
        logger.info("[WeeklyReports] sleeping %s seconds until next run", delay)
        await asyncio.sleep(delay)
        try:
            await generate_weekly_reports()
        except Exception as exc:
            logger.error("[WeeklyReports] generation failed: %s", exc, exc_info=True)
        # Run again a week later
        await asyncio.sleep(60)  # small buffer before recalculating


def seconds_until_next_monday(target_hour: int = 7) -> int:
    now = datetime.utcnow()
    days_ahead = (7 - now.weekday()) % 7
    if days_ahead == 0 and now.hour >= target_hour:
        days_ahead = 7
    next_run = (now + timedelta(days=days_ahead)).replace(
        hour=target_hour, minute=0, second=0, microsecond=0
    )
    return max(60, int((next_run - now).total_seconds()))


async def generate_weekly_reports():
    logger.info("[WeeklyReports] generating summaries")
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                """
                SELECT os.organization_id,
                       org.name,
                       COALESCE(os.admin_email, '') AS admin_email,
                       COALESCE(os.email_notifications, TRUE) AS email_enabled
                FROM organization_settings os
                JOIN organizations org ON org.id = os.organization_id
                WHERE COALESCE(os.weekly_reports, TRUE) = TRUE
                """
            )
        )
        organizations = rows.fetchall()
        if not organizations:
            logger.info("[WeeklyReports] no organizations opted in")
            return

        for org_id, org_name, admin_email, email_enabled in organizations:
            metrics = await build_org_metrics(db, org_id)
            if not metrics:
                continue
            week_start = (
                datetime.utcnow() - timedelta(days=datetime.utcnow().weekday())
            ).date()
            week_label = f"{week_start.isoformat()} week"

            payload = {
                "organization_name": org_name,
                "report_week": week_label,
                "metrics": metrics,
                "target_role": "admin",
                "action_url": "/admin/reports",
            }
            emails: List[str] = []
            if email_enabled and admin_email:
                emails.append(admin_email)

            await publish_event(
                {
                    "type": "weekly.report.generated",
                    "organization_id": org_id,
                    "severity": "info",
                    "payload": payload,
                    "emails": emails,
                }
            )
            logger.info("[WeeklyReports] dispatched summary for org=%s", org_id)


async def build_org_metrics(db, org_id: int) -> Dict[str, Any]:
    stats = {}
    total_projects = await db.scalar(
        text(
            """
            SELECT COUNT(*)
            FROM projects
            WHERE organization_id = :org AND COALESCE(is_archived, FALSE) = FALSE
            """
        ),
        {"org": org_id},
    )
    stats["total_projects"] = int(total_projects or 0)

    active_vulns = await db.scalar(
        text(
            """
            SELECT COUNT(*)
            FROM vulnerabilities v
            JOIN sboms s ON s.id = v.sbom_id
            JOIN projects p ON p.id = s.project_id
            WHERE p.organization_id = :org AND v.is_active = TRUE
            """
        ),
        {"org": org_id},
    )
    stats["active_vulnerabilities"] = int(active_vulns or 0)

    critical_vulns = await db.scalar(
        text(
            """
            SELECT COUNT(*)
            FROM vulnerabilities v
            JOIN sboms s ON s.id = v.sbom_id
            JOIN projects p ON p.id = s.project_id
            WHERE p.organization_id = :org
              AND v.is_active = TRUE
              AND LOWER(COALESCE(v.severity, '')) = 'critical'
            """
        ),
        {"org": org_id},
    )
    stats["critical_vulnerabilities"] = int(critical_vulns or 0)

    new_vulns = await db.scalar(
        text(
            """
            SELECT COUNT(*)
            FROM vulnerabilities v
            JOIN sboms s ON s.id = v.sbom_id
            JOIN projects p ON p.id = s.project_id
            WHERE p.organization_id = :org
              AND v.created_at >= CURRENT_DATE - INTERVAL '7 days'
            """
        ),
        {"org": org_id},
    )
    stats["new_vulnerabilities_last_7d"] = int(new_vulns or 0)

    avg_risk = await db.scalar(
        text(
            """
            SELECT COALESCE(AVG(avg_risk_score),0)
            FROM projects
            WHERE organization_id = :org
            """
        ),
        {"org": org_id},
    )
    stats["average_risk_score"] = float(avg_risk or 0.0)

    top_projects_rows = await db.execute(
        text(
            """
            SELECT name, COALESCE(avg_risk_score,0) AS avg_risk, total_vulnerabilities
            FROM projects
            WHERE organization_id = :org
            ORDER BY avg_risk_score DESC NULLS LAST
            LIMIT 5
            """
        ),
        {"org": org_id},
    )
    stats["top_projects"] = [
        {
            "name": row[0],
            "avg_risk_score": float(row[1] or 0),
            "total_vulnerabilities": int(row[2] or 0),
        }
        for row in top_projects_rows.fetchall()
    ]

    compliance_reports = await db.scalar(
        text(
            """
            SELECT COUNT(*)
            FROM compliance_reports cr
            JOIN projects p ON LOWER(p.name) = LOWER(cr.project_name)
            WHERE p.organization_id = :org
              AND cr.created_at >= CURRENT_DATE - INTERVAL '7 days'
            """
        ),
        {"org": org_id},
    )
    stats["reports_generated_last_7d"] = int(compliance_reports or 0)
    return stats
