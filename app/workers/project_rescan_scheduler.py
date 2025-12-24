import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta

from aiokafka import AIOKafkaProducer
from sqlalchemy import text

from app.core.config import settings
from app.db.session import AsyncSessionLocal

logger = logging.getLogger("project_rescan_scheduler")


async def start_project_rescan_scheduler():
    """
    Loop that periodically checks for projects with enabled rescan settings
    and enqueues vuln.refresh events when due.
    """
    interval_seconds = max(60, settings.RESCAN_SCHEDULER_INTERVAL_MINUTES * 60)
    producer: AIOKafkaProducer | None = None

    while True:
        try:
            if producer is None:
                producer = AIOKafkaProducer(bootstrap_servers=settings.KAFKA_BROKER)
                await producer.start()
                logger.info("[RescanScheduler] Kafka producer ready")

            await _enqueue_due_rescans(producer)
        except Exception as exc:
            logger.error("[RescanScheduler] cycle failed: %s", exc, exc_info=True)
            if producer is not None:
                try:
                    await producer.stop()
                except Exception:
                    pass
            producer = None
        await asyncio.sleep(interval_seconds)


async def _enqueue_due_rescans(producer: AIOKafkaProducer) -> None:
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                """
                SELECT prs.project_id,
                       prs.organization_id,
                       p.name AS project_name,
                       prs.frequency_hours
                FROM project_rescan_settings prs
                JOIN projects p ON p.id = prs.project_id
                WHERE prs.enabled = TRUE
                  AND (prs.next_run_at IS NULL OR prs.next_run_at <= NOW())
                  AND (p.is_archived IS NULL OR p.is_archived = FALSE)
                """
            )
        )
        due_projects = rows.fetchall()
        if not due_projects:
            return

        now = datetime.utcnow()
        for project_id, org_id, project_name, frequency_hours in due_projects:
            if not project_name:
                continue
            payload = _build_refresh_event(
                org_id=org_id,
                project_name=project_name,
                project_id=project_id,
                occurred_at=now,
            )
            try:
                await producer.send_and_wait(
                    settings.VULN_REFRESH_TOPIC,
                    json.dumps(payload).encode("utf-8"),
                    key=project_name.encode("utf-8"),
                )
            except Exception as exc:
                logger.error(
                    "[RescanScheduler] failed to enqueue refresh for project=%s: %s",
                    project_name,
                    exc,
                )
                continue

            next_run = now + timedelta(
                hours=max(1, frequency_hours or settings.DEFAULT_RESCAN_FREQUENCY_HOURS)
            )
            await db.execute(
                text(
                    """
                    UPDATE project_rescan_settings
                    SET last_enqueued_at = :now,
                        next_run_at = :next_run,
                        updated_at = :now
                    WHERE project_id = :pid
                    """
                ),
                {"now": now, "next_run": next_run, "pid": project_id},
            )
        await db.commit()
        logger.info(
            "[RescanScheduler] enqueued %d refresh request(s)", len(due_projects)
        )


def _build_refresh_event(
    *, org_id: int, project_name: str, project_id: int, occurred_at: datetime
) -> dict:
    return {
        "type": "vuln.refresh.requested",
        "version": 1,
        "id": str(uuid.uuid4()),
        "occurred_at": occurred_at.isoformat() + "Z",
        "organization_id": org_id,
        "project_name": project_name,
        "data": {
            "project_id": project_id,
            "project_name": project_name,
            "organization_id": org_id,
            "sbom_id": None,
            "source": "project_rescan",
            "consume_quota": False,
        },
    }
