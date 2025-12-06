# app/workers/kafka_consumer.py
import asyncio
from datetime import datetime, time
import json
import logging
from aiokafka import AIOKafkaConsumer, errors
from sqlalchemy.future import select
from app.db.session import AsyncSessionLocal
from app.db.models import Vulnerability
from app.services.risk_service import save_risk_scores
from app.api.v1.risk import broadcast_to_clients
from sqlalchemy import text

logger = logging.getLogger("risk_consumer")

KAFKA_BROKER = "kafka:9092"
KAFKA_TOPIC = "vuln.processed"
GROUP_ID = "risk-service-consumer"


async def handle_risk_event(sbom_id: str, project: str):
    now = datetime.utcnow()
    async with AsyncSessionLocal() as db:
        # Update project is_scanned to true
        try:
            await db.execute(
                text(
                    """
                    UPDATE projects
                    SET is_scanned = TRUE,
                        last_vuln_scan = :now
                    WHERE name = :p
                """
                ),
                {"p": project, "now": now},
            )
            await db.commit()
            logger.info(f"[ProjectScan] Marked project '{project}' as scanned")
        except Exception as e:
            logger.error(
                f"[ProjectScan] Failed to update is_scanned for {project}: {e}"
            )

        res = await db.execute(
            select(Vulnerability).where(Vulnerability.sbom_id == sbom_id)
        )
        vulns = res.scalars().all()

        risk_scores = await save_risk_scores(vulns, sbom_id, db)

        project_row = await db.execute(
            text("SELECT id FROM projects WHERE name = :project LIMIT 1"),
            {"project": project},
        )
        project_id_row = project_row.fetchone()
        project_id = project_id_row[0] if project_id_row else None

        # Build payload full info
        payload = {
            "type": "scan_complete",
            "sbom_id": sbom_id,
            "project_name": project,
            "risk_scores": risk_scores,
            "vulns": [
                {
                    "id": v.id,
                    "cve": getattr(v, "vuln_id", None),  # <- dùng vuln_id thay cho cve
                    "component": v.component_name,
                    "version": v.component_version,
                    "project_name": v.project_name,
                    "severity": v.severity,
                    "cvss": getattr(v, "cvss_vector", None),
                    "risk_score": next(
                        (
                            r["score"]
                            for r in risk_scores
                            if r["component_name"] == v.component_name
                            and r["component_version"] == v.component_version
                        ),
                        None,
                    ),
                    "osv_meta": getattr(v, "osv_metadata", None),
                    "updated_at": v.updated_at.isoformat() if v.updated_at else None,
                }
                for v in vulns
            ],
            "total_vulns": len(vulns),
            "avg_risk_score": (
                round(sum(r["score"] for r in risk_scores) / len(risk_scores), 2)
                if risk_scores
                else 0
            ),
            "highest_severity": compute_highest_severity([v.severity for v in vulns]),
            "last_scan": datetime.utcnow().isoformat(),
        }

        code_findings = []
        if project_id:
            cf_rows = await db.execute(
                text(
                    """
                    SELECT id,
                           COALESCE(project_name, '') AS project_name,
                           COALESCE(rule_id, '')      AS rule_id,
                           COALESCE(rule_title, '')   AS rule_title,
                           COALESCE(severity, '')     AS severity,
                           COALESCE(file_path, '')    AS file_path,
                           COALESCE(start_line, 0)    AS start_line,
                           COALESCE(end_line, 0)      AS end_line,
                           COALESCE(category, '')     AS category,
                           COALESCE(confidence, '')   AS confidence,
                           COALESCE(message, '')      AS message
                    FROM code_findings
                    WHERE project_id = :project_id
                    ORDER BY created_at DESC
                    LIMIT 500
                    """
                ),
                {"project_id": project_id},
            )
            for row in cf_rows.fetchall():
                code_findings.append(
                    {
                        "id": row[0],
                        "project_name": row[1],
                        "rule_id": row[2],
                        "rule_title": row[3],
                        "severity": row[4],
                        "file_path": row[5],
                        "start_line": row[6],
                        "end_line": row[7],
                        "category": row[8],
                        "confidence": row[9],
                        "message": row[10],
                    }
                )

        payload["code_findings"] = code_findings
        payload["code_findings_count"] = len(code_findings)
        payload["projects"] = [
            {
                "project_name": project,
                "total_vulns": len(vulns),
                "avg_risk_score": (
                    round(sum(r["score"] for r in risk_scores) / len(risk_scores), 2)
                    if risk_scores
                    else 0
                ),
                "highest_severity": compute_highest_severity(
                    [v.severity for v in vulns]
                ),
                "last_scan": datetime.utcnow().isoformat(),
                "code_findings": len(code_findings),
            }
        ]

        await broadcast_to_clients(project, payload)


async def consume_messages():
    max_retries = 10
    delay = 5

    # ---- Connect to Kafka ----
    for attempt in range(1, max_retries + 1):
        try:
            logger.warning(
                f"[Kafka] Attempting connection #{attempt} to broker={KAFKA_BROKER}"
            )
            consumer = AIOKafkaConsumer(
                KAFKA_TOPIC,
                bootstrap_servers=KAFKA_BROKER,
                group_id=GROUP_ID,
                enable_auto_commit=True,
                auto_offset_reset="earliest",
            )
            await consumer.start()
            logger.warning(f"[Kafka] Connected successfully on attempt {attempt}")
            break
        except errors.KafkaConnectionError as e:
            logger.error(f"[Kafka] Connection error #{attempt}: {e}")
            if attempt == max_retries:
                logger.error("[Kafka] Max retries reached. Exiting consumer.")
                return
            await asyncio.sleep(delay)

    logger.warning(f"[Kafka] Consumer started for topic={KAFKA_TOPIC}")

    # ---- Consume messages ----
    try:
        async for msg in consumer:
            try:
                raw = msg.value.decode("utf-8")
                logger.warning(f"[Kafka] Raw message received: {raw}")

                evt = json.loads(raw)
                evt_type = evt.get("type", "vuln.processed")

                project = evt.get("project_name") or evt.get("project")
                if not project:
                    logger.error(f"[Kafka] Event missing project field! {evt}")
                    continue

                # ---- CASE BATCH ----
                if evt_type == "vuln.processed.batch":
                    logger.warning(
                        f"[Kafka] Received BATCH event for project={project}"
                    )
                    records = evt.get("records", [])

                    logger.warning(f"[Kafka] Batch record count: {len(records)}")
                    if not records:
                        logger.warning("[Kafka] Empty batch → handling empty case")
                        await handle_risk_event(
                            f"sbom-limit-{int(time.time())}", project
                        )
                        continue

                    for record in records:
                        sbom_id = record.get("sbom_id")
                        logger.warning(f"[Kafka] Handling batch SBOM {sbom_id}")
                        await handle_risk_event(sbom_id, project)
                    continue

                # ---- CASE NORMAL vuln.processed ----
                sbom_id = evt.get("sbom_id")
                if not sbom_id:
                    logger.error(f"[Kafka] Missing sbom_id in event: {evt}")
                    continue

                logger.warning(
                    f"[Kafka] Received NORMAL vuln.processed | sbom_id={sbom_id} | project={project}"
                )
                await handle_risk_event(sbom_id, project)

            except Exception as e:
                logger.exception(f"[Kafka] ERROR while processing message: {e}")

    finally:
        await consumer.stop()
        logger.warning("[Kafka] Consumer stopped gracefully")


def compute_highest_severity(severities: list[str]) -> str:
    """
    Severity order: critical > high > moderate > low > none
    """
    sev_order = ["critical", "high", "moderate", "low", "none"]
    lower = [s.lower() for s in severities if s and s.strip()]  # normalize & skip empty
    for s in sev_order:
        if s in lower:
            return s
    return "none"
