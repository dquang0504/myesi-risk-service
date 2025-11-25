import asyncio
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.db.models import Vulnerability
from app.schemas.risk import RiskScoreResponse, RiskTrendResponse
from app.db import session as db_session
from app.services.risk_service import (
    save_risk_scores,
    get_risk_trends,
)
from app.core.config import settings
from jose import jwt

router = APIRouter(prefix="/api/risk", tags=["Risk"])
logger = logging.getLogger("risk_consumer")


# ----------------------------
# SSE streaming store
# ----------------------------
SSE_CLIENTS: dict[str, list[asyncio.Queue]] = {}
LAST_EVENTS: dict[str, dict] = {}  # store last event per project


async def broadcast_to_clients(project: str, payload: dict):
    """
    Send a payload to all clients listening for this project or '*'.
    Cache the last event for new clients to receive immediately.
    """
    # Log hiện trạng SSE clients trước khi broadcast
    logger.info(f"[SSE] Broadcasting for project={project}")
    logger.info(f"[SSE] Current SSE_CLIENTS keys: {list(SSE_CLIENTS.keys())}")
    for k, queues in SSE_CLIENTS.items():
        logger.info(f"[SSE] Project={k}, queue count={len(queues)}")
    logger.info(f"[SSE] LAST_EVENTS keys before update: {list(LAST_EVENTS.keys())}")

    # Cache last event per project
    LAST_EVENTS[project] = payload

    targets = []
    # Clients listening to the specific project
    if project in SSE_CLIENTS:
        targets.extend(SSE_CLIENTS[project])
    # Clients listening to all projects ("*")
    if "*" in SSE_CLIENTS:
        targets.extend(SSE_CLIENTS["*"])

    # ensure JSON serializable
    safe_payload = json.loads(json.dumps(payload, default=str))
    for q in targets:
        await q.put(safe_payload)
        logger.info(f"[SSE] Pushed event to queue {q} for project={project}")

    logger.info(f"[SSE] LAST_EVENTS keys after update: {list(LAST_EVENTS.keys())}")
    logger.info(
        f"[SSE] Broadcast complete for project={project}, target queues={len(targets)}"
    )


# ----------------------------
# HTTP Endpoints
# ----------------------------


@router.get("/score", response_model=List[RiskScoreResponse])
async def risk_score(sbom_id: str, db: AsyncSession = Depends(db_session.get_db)):
    # Query all vulnerabilities for this SBOM
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.sbom_id == sbom_id)
    )
    vulns = result.scalars().all()
    # Compute risk scores
    results = await save_risk_scores(vulns, sbom_id, db)
    return results


@router.get("/trends", response_model=List[RiskTrendResponse])
async def risk_trends(db: AsyncSession = Depends(db_session.get_db)):
    trends = await get_risk_trends(db)
    return trends


# ---------------- SSE client store ----------------
SSE_CLIENTS: dict[str, list[asyncio.Queue]] = {}
LAST_EVENTS: dict[str, dict] = {}  # last event per project


# ---------------- JWT validation helper ----------------
def verify_jwt(token: str):
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except Exception:
        return None


# ---------------- SSE broadcast ----------------
async def broadcast(project: str, payload: dict):
    LAST_EVENTS[project] = payload

    targets = []
    if project in SSE_CLIENTS:
        targets.extend(SSE_CLIENTS[project])
    if "*" in SSE_CLIENTS:
        targets.extend(SSE_CLIENTS["*"])

    safe_json = json.loads(json.dumps(payload, default=str))
    for q in targets:
        await q.put(safe_json)

    logger.info(f"[SSE] broadcast → {project} → {len(targets)} clients")


# ---------------- SSE endpoint ----------------
@router.get("/stream")
async def stream_risk_events(request: Request):
    """
    SSE endpoint: ?project_name=<name> or * for global
    JWT must be in Authorization header
    """
    project = request.query_params.get("project_name", "*")

    # --- JWT check ---
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing JWT")
    token = auth_header.split(" ")[1]
    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid JWT")

    # --- Queue for this client ---
    queue = asyncio.Queue()
    SSE_CLIENTS.setdefault(project, []).append(queue)

    # Send last events immediately
    if project in LAST_EVENTS:
        await queue.put(LAST_EVENTS[project])
    if project == "*" and LAST_EVENTS:
        for proj_name, payload in LAST_EVENTS.items():
            await queue.put(payload)

    logger.info(f"[SSE] Client connected for project={project}")

    async def event_generator():
        try:
            while True:
                data = await queue.get()
                yield f"data: {json.dumps(data)}\n\n"
                # Check if client disconnected
                if await request.is_disconnected():
                    break
        except asyncio.CancelledError:
            pass
        finally:
            SSE_CLIENTS[project].remove(queue)
            logger.info(f"[SSE] Client disconnected from project={project}")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "https://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
        },
    )


async def send_broadcast(project, payload):
    # Instead of POSTing to internal HTTP endpoint
    await broadcast_to_clients(project, payload)


@router.get("/analytics")
async def risk_distribution(db: AsyncSession = Depends(db_session.get_db)):
    """
    Returns:
      - overallRisk: average risk score (0–10)
      - distribution: count of vulnerabilities by severity
    """

    # -------------------------------
    # 1) Severity Distribution (vulnerabilities table)
    # -------------------------------
    sev_sql = text(
        """
        SELECT severity
        FROM vulnerabilities
    """
    )
    sev_result = await db.execute(sev_sql)
    rows = sev_result.fetchall()

    sev_count = {
        "critical": 0,
        "high": 0,
        "moderate": 0,
        "low": 0,
    }

    for (sev,) in rows:
        if not sev:
            continue
        s = sev.lower()
        if s in sev_count:
            sev_count[s] += 1

    # -------------------------------
    # 2) Overall Risk (risk_scores table)
    # -------------------------------
    risk_sql = text(
        """
        SELECT score
        FROM risk_scores
        WHERE score IS NOT NULL
    """
    )
    risk_result = await db.execute(risk_sql)
    score_rows = [r[0] for r in risk_result.fetchall() if r[0] is not None]

    if len(score_rows) == 0:
        overall = 0.0
    else:
        overall = sum(score_rows) / len(score_rows)
        if overall > 10:
            overall = 10.0

    return {
        "overallRisk": round(overall, 2),
        "distribution": [
            {"name": "Critical", "value": sev_count["critical"]},
            {"name": "High", "value": sev_count["high"]},
            {"name": "Moderate", "value": sev_count["moderate"]},
            {"name": "Low", "value": sev_count["low"]},
        ],
    }


@router.get("/heatmap")
async def risk_heatmap(
    type: str = "projects", db: AsyncSession = Depends(db_session.get_db)
):
    if type != "projects":
        raise HTTPException(status_code=400, detail="Only 'projects' heatmap supported")

    sql = text(
        """
        SELECT 
            p.name AS project_name,
            DATE(v.created_at) AS day,
            AVG(rs.score) AS avg_score
        FROM vulnerabilities v
        JOIN sboms s 
            ON s.id = v.sbom_id
        JOIN projects p 
            ON p.id = s.project_id
        LEFT JOIN risk_scores rs
            ON rs.sbom_id = v.sbom_id
           AND rs.component_name = v.component_name
           AND rs.component_version = v.component_version
        WHERE v.created_at >= CURRENT_DATE - INTERVAL '7 days'
        GROUP BY p.name, DATE(v.created_at)
        ORDER BY p.name, day;
    """
    )

    result = await db.execute(sql)
    rows = result.fetchall()

    data = []
    for project, day, score in rows:
        day_label = day.strftime("%a")  # Mon/Tue/Wed
        data.append(
            {
                "x": day_label,
                "y": project,
                "value": float(score) if score is not None else None,
            }
        )

    return {"heatmap": data}
