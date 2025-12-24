# app/workers/kafka_consumer.py
import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from aiokafka import AIOKafkaConsumer, errors
from sqlalchemy import text
from sqlalchemy.future import select

from app.api.v1.risk import broadcast_to_clients
from app.db.models import Vulnerability
from app.db.session import AsyncSessionLocal
from app.services.risk_service import save_risk_scores

logger = logging.getLogger("risk_consumer")

KAFKA_BROKER = "kafka:9092"
KAFKA_TOPIC = "vuln.processed"
GROUP_ID = "risk-service-consumer"


def is_uuid(value: str) -> bool:
    """Return True if value is a valid UUID string."""
    try:
        uuid.UUID(str(value))
        return True
    except Exception:
        return False


def compute_highest_severity(severities: List[str]) -> str:
    """
    Severity order: critical > high > moderate > low > none
    """
    sev_order = ["critical", "high", "moderate", "low", "none"]
    lower = [s.lower() for s in severities if s and s.strip()]
    for s in sev_order:
        if s in lower:
            return s
    return "none"


async def mark_project_scanned(project: str) -> None:
    """Update project scan flags regardless of vulnerability results."""
    now = datetime.utcnow()
    async with AsyncSessionLocal() as db:
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


async def fetch_project_id(db, project: str) -> Optional[str]:
    """Fetch project id by project name."""
    project_row = await db.execute(
        text("SELECT id FROM projects WHERE name = :project LIMIT 1"),
        {"project": project},
    )
    row = project_row.fetchone()
    return row[0] if row else None


async def fetch_code_findings(db, project_id: str) -> List[Dict[str, Any]]:
    """Fetch recent code findings for a given project_id."""
    rows = await db.execute(
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

    out: List[Dict[str, Any]] = []
    for row in rows.fetchall():
        out.append(
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
    return out


async def build_and_broadcast_payload(sbom_id: str, project: str) -> None:
    """Build a full payload and broadcast to websocket clients."""
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(Vulnerability).where(
                Vulnerability.sbom_id == sbom_id, Vulnerability.is_active.is_(True)
            )
        )
        raw_vulns = res.scalars().all()

        # Deduplicate vulnerabilities (same vuln_id/component/version) to avoid repeated rows per scan
        unique_map: Dict[str, Vulnerability] = {}
        for v in raw_vulns:
            key = (
                f"{getattr(v, 'vuln_id', '')}|{v.component_name}|{v.component_version}"
            )
            existing = unique_map.get(key)
            if not existing:
                unique_map[key] = v
            else:
                prev_ts = existing.updated_at or datetime.min
                cur_ts = v.updated_at or datetime.min
                if cur_ts > prev_ts:
                    unique_map[key] = v
        vulns = list(unique_map.values())

        risk_scores = await save_risk_scores(vulns, sbom_id, db)

        project_id = await fetch_project_id(db, project)

        code_findings: List[Dict[str, Any]] = []
        if project_id:
            code_findings = await fetch_code_findings(db, project_id)

        payload: Dict[str, Any] = {
            "type": "scan_complete",
            "sbom_id": sbom_id,
            "project_name": project,
            "risk_scores": risk_scores,
            "vulns": [
                {
                    "id": v.id,
                    "cve": getattr(v, "vuln_id", None),
                    "component": v.component_name,
                    "version": v.component_version,
                    "project_name": v.project_name,
                    "severity": v.severity,
                    "cvss": getattr(v, "cvss_vector", None),
                    "risk_score": next(
                        (
                            r["score"]
                            for r in risk_scores
                            if r.get("component_name") == v.component_name
                            and r.get("component_version") == v.component_version
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
            "code_findings": code_findings,
            "code_findings_count": len(code_findings),
            "projects": [
                {
                    "project_name": project,
                    "total_vulns": len(vulns),
                    "avg_risk_score": (
                        round(
                            sum(r["score"] for r in risk_scores) / len(risk_scores), 2
                        )
                        if risk_scores
                        else 0
                    ),
                    "highest_severity": compute_highest_severity(
                        [v.severity for v in vulns]
                    ),
                    "last_scan": datetime.utcnow().isoformat(),
                    "code_findings": len(code_findings),
                }
            ],
        }

        await broadcast_to_clients(project, payload)


async def handle_risk_event(sbom_id: str, project: str) -> None:
    """
    Main handler for a single SBOM scan completion.
    It marks project scanned, then queries vulnerabilities by sbom_id (UUID),
    computes risk scores, and broadcasts to clients.
    """
    await mark_project_scanned(project)

    if not is_uuid(sbom_id):
        logger.warning(
            f"[Kafka] Ignoring event due to invalid sbom_id (not UUID): {sbom_id}"
        )
        return

    await build_and_broadcast_payload(sbom_id, project)


def extract_project(evt: Dict[str, Any]) -> Optional[str]:
    """Extract project name from common event fields."""
    return evt.get("project_name") or evt.get("project")


def extract_batch_records(evt: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract batch records from the event schema.
    Expected structure:
      {
        "type": "vuln.processed.batch",
        ...
        "data": {
          "records": [ ... ]
        }
      }
    """
    data = evt.get("data") or {}
    records = data.get("records") or []
    if isinstance(records, list):
        return records
    return []


async def consume_messages() -> None:
    max_retries = 10
    delay = 5

    consumer: Optional[AIOKafkaConsumer] = None

    # Connect to Kafka with retries
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

    if consumer is None:
        logger.error("[Kafka] Consumer not initialized. Exiting.")
        return

    logger.warning(f"[Kafka] Consumer started for topic={KAFKA_TOPIC}")

    try:
        async for msg in consumer:
            try:
                raw = msg.value.decode("utf-8")
                logger.warning(f"[Kafka] Raw message received: {raw}")

                evt = json.loads(raw)
                evt_type = evt.get("type", "vuln.processed")

                project = extract_project(evt)
                if not project:
                    logger.error(f"[Kafka] Event missing project field! {evt}")
                    continue

                # Batch case
                if evt_type == "vuln.processed.batch":
                    logger.warning(
                        f"[Kafka] Received BATCH event for project={project}"
                    )

                    records = extract_batch_records(evt)
                    logger.warning(f"[Kafka] Batch record count: {len(records)}")

                    # If batch is empty, just mark project scanned and do not query vulnerabilities
                    if not records:
                        logger.warning(
                            "[Kafka] Empty batch → marking project scanned only"
                        )
                        await mark_project_scanned(project)
                        continue

                    for record in records:
                        sbom_id = record.get("sbom_id")
                        if not sbom_id:
                            logger.warning(
                                f"[Kafka] Batch record missing sbom_id: {record}"
                            )
                            continue
                        logger.warning(f"[Kafka] Handling batch SBOM {sbom_id}")
                        await handle_risk_event(sbom_id, project)
                    continue

                # Normal case
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
        try:
            await consumer.stop()
        except Exception:
            pass
        logger.warning("[Kafka] Consumer stopped gracefully")
