import asyncio
import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.db.models import Vulnerability
from app.schemas.risk import RiskScoreResponse, RiskTrendResponse
from collections import defaultdict
from app.db import session as db_session
from app.services.risk_service import (
    get_org_id_from_header,
    save_risk_scores,
    get_risk_trends,
)
from app.utils.report_helper import compute_update_score
from app.services.risk_report_service import generate_risk_overview_report
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
async def risk_distribution(
    org_id: int = Depends(get_org_id_from_header),
    db: AsyncSession = Depends(db_session.get_db),
):
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
        SELECT v.severity
        FROM vulnerabilities v
        JOIN projects p ON v.project_id = p.id
        WHERE p.organization_id = :org_id
    """
    )
    sev_result = await db.execute(sev_sql, {"org_id": org_id})
    rows = sev_result.fetchall()

    sev_count = {
        "critical": 0,
        "high": 0,
        "medium": 0,
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
        SELECT rs.score
        FROM risk_scores rs
        JOIN sboms s ON rs.sbom_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE rs.score IS NOT NULL
          AND p.organization_id = :org_id
    """
    )
    risk_result = await db.execute(risk_sql, {"org_id": org_id})
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
            {"name": "medium", "value": sev_count["medium"]},
            {"name": "Low", "value": sev_count["low"]},
        ],
    }


@router.get("/heatmap")
async def risk_heatmap(
    org_id: int = Depends(get_org_id_from_header),
    type: str = "projects",
    db: AsyncSession = Depends(db_session.get_db),
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
          AND v.is_active = TRUE
          AND p.organization_id = :org_id
        GROUP BY p.name, DATE(v.created_at)
        ORDER BY p.name, day;
    """
    )

    result = await db.execute(sql, {"org_id": org_id})
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


@router.get("/analyst/dashboard")
async def analyst_dashboard(db: AsyncSession = Depends(db_session.get_db)):
    """
    Aggregated analytics for the Analyst Dashboard:
      - stats: total risks, critical issues, compliance score, reports count
      - distribution: severity breakdown
      - complianceChecklist: quick control coverage snapshot
      - riskTrend: daily average risk scores
    """
    # --- Core stats (only active vulnerabilities) ---
    active_rows = await db.execute(
        text(
            """
        SELECT LOWER(severity) AS severity, osv_metadata, sbom_id, component_name, component_version
        FROM vulnerabilities 
        WHERE is_active = TRUE
      """
        )
    )
    active_records = active_rows.fetchall()
    active_severities = [row[0] for row in active_records if row[0]]

    total_risks = len(active_severities)
    critical_issues = sum(1 for s in active_severities if str(s).lower() == "critical")

    completed_reports = (
        await db.scalar(
            text(
                """
        SELECT COUNT(*) 
        FROM compliance_reports 
        WHERE status = 'completed'
      """
            )
        )
        or 0
    )

    total_reports = (
        await db.scalar(
            text(
                """
        SELECT COUNT(*) 
        FROM compliance_reports
      """
            )
        )
        or 0
    )
    total_fixed = (
        await db.scalar(
            text(
                """
        SELECT COUNT(*) 
        FROM vulnerabilities
        WHERE is_active = FALSE
      """
            )
        )
        or 0
    )

    # Compliance score: align with weighted_compliance logic (using active vulns only)
    # Pull control mappings that are tied to active vulnerabilities
    control_rows = await db.execute(
        text(
            """
        SELECT cm.control_id, COUNT(*) AS affected
        FROM control_mappings cm
        JOIN vulnerabilities v
          ON v.sbom_id = cm.sbom_id
         AND v.component_name = cm.component_name
         AND v.component_version = cm.component_version
        WHERE v.is_active = TRUE
        GROUP BY cm.control_id
      """
        )
    )
    control_counts = (
        {r[0]: int(r[1]) for r in control_rows.fetchall()} if control_rows else {}
    )

    # Load weights (default ISO_27001:2022)
    weight_rows = await db.execute(
        text(
            """
        SELECT scope_key, weight
        FROM compliance_weights
        WHERE standard = 'ISO_27001:2022' AND applicable = TRUE
      """
        )
    )
    weights = {r[0]: float(r[1]) for r in weight_rows.fetchall()} if weight_rows else {}

    detailed = {}
    total_weight = 0.0
    weighted_sum = 0.0

    if control_counts:
        for ctrl, affected in control_counts.items():
            weight = weights.get(ctrl, 0.01)
            total_weight += weight
            score = max(0.0, 1.0 - 0.1 * affected)
            weighted_sum += score * weight
            detailed[ctrl] = round(score * 100, 2)
    else:
        severity_weights = {
            "critical": 0.25,
            "high": 0.25,
            "medium": 0.15,
            "low": 0.10,
            "unknown": 0.05,
        }
        for sev, count in (
            (s, active_severities.count(s)) for s in set(active_severities or [])
        ):
            w = severity_weights.get(str(sev).lower(), 0.05)
            score = max(0.0, 1.0 - 0.5 * (count > 0))
            weighted_sum += score * w
            total_weight += w
            detailed[sev] = round(score * 100, 2)

    # Prefer latest compliance reports per project to align with per-project report logic
    # Per-project compliance score (active vuln -> score, no vuln -> 100)
    project_rows = await db.execute(
        text(
            """
        SELECT p.id,
               p.name,
               COALESCE(av.active_vulns, 0) AS active_vulns,
               cr.score AS report_score
        FROM projects p
        LEFT JOIN (
            SELECT s.project_id, COUNT(*) AS active_vulns
            FROM vulnerabilities v
            JOIN sboms s ON s.id = v.sbom_id
            WHERE v.is_active = TRUE
            GROUP BY s.project_id
        ) av ON av.project_id = p.id
        LEFT JOIN (
            SELECT DISTINCT ON (project_name)
                   project_name,
                   COALESCE((report_data->>'compliance_score')::numeric, 0) AS score
            FROM compliance_reports
            WHERE status = 'completed'
            ORDER BY project_name, created_at DESC
        ) cr ON cr.project_name = p.name
      """
        )
    )

    project_scores: list[float] = []
    comp_scores: list[float] = []

    for pid, pname, active_vulns, report_score in project_rows.fetchall():
        active_count = int(active_vulns or 0)
        if active_count == 0:
            project_scores.append(100.0)
            continue
        if report_score is not None:
            score_val = float(report_score)
            project_scores.append(score_val)
            comp_scores.append(score_val)
            continue

        # fallback using active vulnerabilities of this project
        per_proj_rows = await db.execute(
            text(
                """
            SELECT LOWER(COALESCE(severity,'')) AS sev, osv_metadata
            FROM vulnerabilities v
            JOIN sboms s ON s.id = v.sbom_id
            WHERE s.project_id = :pid AND v.is_active = TRUE
          """
            ),
            {"pid": pid},
        )
        pv = per_proj_rows.fetchall()
        if not pv:
            project_scores.append(100.0)
            continue

        # reuse severity_weights approach
        severity_weights = {
            "critical": 0.25,
            "high": 0.25,
            "medium": 0.15,
            "low": 0.10,
            "unknown": 0.05,
        }
        weighted_sum = 0.0
        total_weight = 0.0
        sev_map = {}
        for sev, _ in pv:
            if not sev:
                continue
            sev_map[sev] = sev_map.get(sev, 0) + 1
        for sev, count in sev_map.items():
            w = severity_weights.get(str(sev).lower(), 0.05)
            score = max(0.0, 1.0 - 0.5 * (count > 0))
            weighted_sum += score * w
            total_weight += w
        cf = (weighted_sum / total_weight) if total_weight > 0 else 1.0
        update_score = compute_update_score(
            vuln_records=[{"osv_metadata": rec[1]} for rec in pv], sbom_updated_at=None
        )
        fallback_score = round(((cf * 0.8) + (update_score / 100.0) * 0.2) * 100, 2)
        project_scores.append(fallback_score)

    if project_scores:
        compliance_score = round(sum(project_scores) / len(project_scores), 2)
        min_compliance = min(project_scores)
    else:
        compliance_score = 100.0
        min_compliance = 100.0

    # --- Severity distribution ---
    dist_rows = await db.execute(
        text(
            """
        SELECT LOWER(severity) AS severity, COUNT(*) 
        FROM vulnerabilities 
        WHERE is_active = TRUE
        GROUP BY LOWER(severity)
      """
        )
    )
    sev_counts = defaultdict(int, {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for sev, cnt in dist_rows:
        if sev:
            key = str(sev).lower()
            if key == "medium":
                key = "medium"
            sev_counts[key] += cnt

    distribution = [
        {"name": "Critical", "value": sev_counts["critical"]},
        {"name": "High", "value": sev_counts["high"]},
        {"name": "medium", "value": sev_counts["medium"]},
        {"name": "Low", "value": sev_counts["low"]},
    ]

    # --- Compliance checklist driven by active vulnerabilities ---
    if total_risks == 0:
        compliance_checklist = [
            {"name": "ISO_27001", "status": True},
            {"name": "NIST_SP_800_53", "status": True},
            {"name": "OWASP", "status": True},
        ]
    else:
        has_crit_high = any(
            str(s).lower() in ("critical", "high") for s in active_severities
        )
        # ISO / NIST use average/worst compliance scores when available
        iso_ok = (
            (min_compliance >= 85)
            if comp_scores
            else (not has_crit_high and compliance_score >= 85)
        )
        nist_ok = (
            (min_compliance >= 75)
            if comp_scores
            else (not has_crit_high and compliance_score >= 75)
        )
        # OWASP: flag if any critical active
        owasp_ok = sev_counts["critical"] == 0
        compliance_checklist = [
            {"name": "ISO_27001", "status": iso_ok},
            {"name": "NIST_SP_800_53", "status": nist_ok},
            {"name": "OWASP", "status": owasp_ok},
        ]

    # --- Risk trend: daily average of saved risk scores (all time) ---
    trend_rows = await db.execute(
        text(
            """
        SELECT DATE(created_at) AS day, ROUND(AVG(score)::numeric, 2) AS avg_score
        FROM risk_scores
        WHERE score IS NOT NULL
        GROUP BY DATE(created_at)
        ORDER BY day
      """
        )
    )
    trend = [
        {"date": day.isoformat(), "score": float(avg) if avg is not None else 0.0}
        for day, avg in trend_rows
    ]

    return {
        "stats": {
            "totalRisks": total_risks,
            "criticalIssues": critical_issues,
            "complianceScore": compliance_score,
            "reportsGenerated": (
                completed_reports if completed_reports else total_reports
            ),
            "fixedVulnerabilities": total_fixed,
        },
        "distribution": distribution,
        "complianceChecklist": compliance_checklist,
        "riskTrend": trend,
    }


@router.get("/overview")
async def risk_overview(db: AsyncSession = Depends(db_session.get_db)):
    """
    Aggregated risk overview for analysts.
    """
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
    avg_risk_score = (
        await db.scalar(text("SELECT COALESCE(AVG(avg_risk_score),0) FROM projects"))
        or 0.0
    )

    # Projects at risk (based on active vulnerabilities only)
    projects_at_risk = (
        await db.scalar(
            text(
                """
            SELECT COUNT(*) FROM (
              SELECT p.id,
                     AVG(rs.score) AS avg_risk,
                     COUNT(v.id) AS active_vulns
              FROM projects p
              LEFT JOIN sboms s ON s.project_id = p.id
              LEFT JOIN vulnerabilities v
                ON v.sbom_id = s.id
               AND v.is_active = TRUE
              LEFT JOIN risk_scores rs
                ON rs.sbom_id = v.sbom_id
               AND rs.component_name = v.component_name
               AND rs.component_version = v.component_version
              GROUP BY p.id
            ) t
            WHERE t.active_vulns > 0 AND t.avg_risk >= 7
            """
            )
        )
        or 0
    )

    # Severity distribution
    dist_rows = await db.execute(
        text(
            """
            SELECT LOWER(COALESCE(severity, 'unknown')) AS severity, COUNT(*)
            FROM vulnerabilities
            WHERE is_active = TRUE
            GROUP BY LOWER(COALESCE(severity, 'unknown'))
            """
        )
    )
    dist = [
        {"name": ("medium" if sev == "medium" else sev.title()), "value": cnt}
        for sev, cnt in dist_rows.fetchall()
    ]

    # Trend (last 30 days per severity) - include historical (not just active) to show scan history
    trend_rows = await db.execute(
        text(
            """
            SELECT DATE(created_at) AS day, LOWER(COALESCE(severity,'unknown')) AS sev, COUNT(*)
            FROM vulnerabilities
            WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(created_at), LOWER(COALESCE(severity,'unknown'))
            ORDER BY day
            """
        )
    )
    trend_map = {}
    for day, sev, cnt in trend_rows.fetchall():
        key = day.isoformat()
        entry = trend_map.setdefault(
            key, {"date": key, "critical": 0, "high": 0, "medium": 0, "low": 0}
        )
        sev_key = "medium" if sev == "medium" else sev
        if sev_key in entry:
            entry[sev_key] += cnt
    trend = list(trend_map.values())

    # Categories from control mappings tied to active vulnerabilities
    cat_rows = await db.execute(
        text(
            """
            SELECT LOWER(COALESCE(cm.category,'uncategorized')) AS category, COUNT(*)
            FROM control_mappings cm
            JOIN vulnerabilities v
              ON v.sbom_id = cm.sbom_id
             AND v.component_name = cm.component_name
             AND v.component_version = cm.component_version
            WHERE v.is_active = TRUE
            GROUP BY LOWER(COALESCE(cm.category,'uncategorized'))
            """
        )
    )
    categories = [
        {"category": cat.title(), "count": cnt} for cat, cnt in cat_rows.fetchall()
    ]

    # Project risk scores
    proj_rows = await db.execute(
        text(
            """
            SELECT p.name,
                   COALESCE(AVG(rs.score), 0) AS avg_risk,
                   COUNT(v.id) AS active_vulns
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
    project_risks = []
    for name, score, active in proj_rows.fetchall():
        avg_risk_val = float(score) if score is not None else 0.0
        project_risks.append(
            {
                "project": name,
                "score": avg_risk_val if active > 0 else 0.0,
                "activeVulns": int(active),
            }
        )

    return {
        "metrics": {
            "totalRisks": total_active,
            "criticalIssues": critical,
            "avgRiskScore": round(float(avg_risk_score), 2),
            "projectsAtRisk": projects_at_risk,
            "fixedVulnerabilities": total_fixed,
        },
        "distribution": dist,
        "trend": trend,
        "categories": categories,
        "projectRisks": project_risks,
        "lastUpdated": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/overview/report")
async def risk_overview_report(db: AsyncSession = Depends(db_session.get_db)):
    """
    Generate a global risk overview PDF (not per project).
    """
    try:
        content, mime, filename = await generate_risk_overview_report(db=db)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")

    return Response(
        content=content,
        media_type=mime,
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
        },
    )


@router.get("/compliance/overview")
async def compliance_overview(db: AsyncSession = Depends(db_session.get_db)):
    """
    Compliance overview across projects based on latest compliance reports and active controls.
    """
    # Latest compliance scores per project (completed reports)
    score_rows = await db.execute(
        text(
            """
        SELECT DISTINCT ON (project_name)
               project_name,
               report_data,
               created_at,
               status
        FROM compliance_reports
        WHERE status = 'completed'
        ORDER BY project_name, created_at DESC
        """
        )
    )
    score_fetch = score_rows.fetchall()
    scores = []
    for r in score_fetch:
        try:
            data = json.loads(r[1] or "{}")
        except Exception:
            data = {}
        scores.append(
            {
                "project_name": r[0],
                "score": float(data.get("compliance_score", 0) or 0),
                "created_at": r[2],
                "status": r[3],
                "report_data": data,
            }
        )

    overall_score = (
        round(sum(s["score"] for s in scores) / len(scores), 2) if scores else 100.0
    )

    # Derive frameworks from compliance_weights distinct standards; if none, default ISO_27001:2022
    std_rows = await db.execute(
        text("SELECT DISTINCT standard FROM compliance_weights")
    )
    standards = [r[0] for r in std_rows.fetchall()] or ["ISO_27001:2022"]
    # Aggregate per-standard score from reports if available
    std_scores = {std: [] for std in standards}
    for s in scores:
        data = s.get("report_data") or {}
        per_std = data.get("per_standard_scores") or {}
        for std, val in per_std.items():
            if std in std_scores:
                try:
                    std_scores[std].append(float(val))
                except Exception:
                    pass
    frameworks = []
    for std in standards:
        if std_scores.get(std):
            score = round(sum(std_scores[std]) / len(std_scores[std]), 2)
        else:
            score = overall_score
        status = "Compliant"
        if score < 60:
            status = "Needs Review"
        elif score < 85:
            status = "Partially"
        frameworks.append({"name": std, "score": score, "status": status})

    # Controls with active vulnerabilities mapped
    ctrl_rows = await db.execute(
        text(
            """
        SELECT cm.control_id,
               COALESCE(cm.control_title,'') AS title,
               COALESCE(cm.category,'Uncategorized') AS category,
               COUNT(DISTINCT v.id) AS occurrences
        FROM control_mappings cm
        JOIN sboms s ON s.id = cm.sbom_id
        JOIN vulnerabilities v ON v.sbom_id = s.id
        WHERE v.is_active = TRUE
        GROUP BY cm.control_id, cm.control_title, cm.category
        ORDER BY occurrences DESC
        LIMIT 10
        """
        )
    )
    controls = [
        {
            "id": cid,
            "name": title,
            "category": cat,
            "occurrences": int(occ),
        }
        for cid, title, cat, occ in ctrl_rows.fetchall()
    ]

    # Recent compliance reports
    recent_rows = await db.execute(
        text(
            """
        SELECT project_name,
               status,
               created_at,
               generated_by,
               report_url,
               report_data
        FROM compliance_reports
        ORDER BY created_at DESC
        LIMIT 5
        """
        )
    )
    recent = []
    for r in recent_rows.fetchall():
        try:
            data = json.loads(r[5] or "{}")
        except Exception:
            data = {}
        recent.append(
            {
                "project_name": r[0],
                "status": r[1],
                "date": r[2].isoformat() if r[2] else None,
                "score": float(data.get("compliance_score", 0) or 0),
                "auditor_id": r[3],
                "report_url": r[4],
                "findings": data.get("vulnerabilities") or {},
            }
        )

    # Build project scores with extra metadata
    proj_rows = await db.execute(
        text(
            """
        SELECT DISTINCT ON (cr.project_name)
               cr.project_name,
               cr.created_at,
               cr.status,
               cr.report_url,
               cr.generated_by,
               cr.report_data,
               u.email
        FROM compliance_reports cr
        LEFT JOIN users u ON u.id = cr.generated_by
        WHERE cr.report_type = 'compliance'
        ORDER BY cr.project_name, cr.created_at DESC
      """
        )
    )

    project_scores = []
    for r in proj_rows.fetchall():
        try:
            data = json.loads(r[5] or "{}")
        except Exception:
            data = {}
        vuln_stats = data.get("vulnerabilities") or {}
        findings_total = sum(vuln_stats.values()) if isinstance(vuln_stats, dict) else 0
        critical_count = (
            vuln_stats.get("critical", 0) if isinstance(vuln_stats, dict) else 0
        )
        project_scores.append(
            {
                "project_name": r[0],
                "score": float(data.get("compliance_score", 0) or 0),
                "created_at": r[1],
                "status": r[2],
                "report_url": r[3],
                "auditor": r[6],
                "findings": findings_total,
                "critical": critical_count,
            }
        )

    trend_rows = await db.execute(
        text(
            """
        SELECT date_trunc('day', created_at) AS day, 
               AVG((report_data->>'compliance_score')::numeric) AS avg_score
        FROM compliance_reports
        WHERE report_type = 'compliance'
          AND created_at >= now() - interval '30 days'
        GROUP BY day
        ORDER BY day
        """
        )
    )
    trend_points = []
    for row in trend_rows.fetchall():
        created_at, score_val = row
        trend_points.append(
            {
                "date": (
                    created_at.isoformat()
                    if created_at
                    else datetime.utcnow().isoformat()
                ),
                "score": float(score_val or 0),
            }
        )
    if not trend_points:
        trend_points.append(
            {
                "date": datetime.utcnow().isoformat(),
                "score": overall_score,
            }
        )

    return {
        "overallScore": overall_score,
        "frameworks": frameworks,
        "controls": controls,
        "recentReports": recent,
        "projectScores": [
            {
                "project_name": s["project_name"],
                "score": s["score"],
                "created_at": s["created_at"].isoformat() if s["created_at"] else None,
                "status": s["status"],
                "report_url": s["report_url"],
                "auditor": s["auditor"],
                "findings": s["findings"],
                "critical": s["critical"],
            }
            for s in project_scores
        ],
        "trend": trend_points,
    }
