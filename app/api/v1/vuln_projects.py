from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db import session as db_session
from app.schemas.rescan import (
    BulkRescanSettingsRequest,
    RescanSettingsRequest,
    RescanSettingsResponse,
)
from app.services.risk_service import get_org_id_from_header

router = APIRouter(prefix="/api/vuln/projects", tags=["Vulnerability Rescan"])


async def _assert_project_access(
    db: AsyncSession, project_id: int, org_id: int
) -> None:
    exists = await db.scalar(
        text(
            """
            SELECT 1
            FROM projects
            WHERE id = :pid
              AND organization_id = :org
            """
        ),
        {"pid": project_id, "org": org_id},
    )
    if not exists:
        raise HTTPException(status_code=404, detail="Project not found")


async def _fetch_rescan_setting(
    db: AsyncSession, project_id: int, org_id: int
) -> RescanSettingsResponse:
    row = await db.execute(
        text(
            """
            SELECT project_id, enabled, frequency_hours, last_enqueued_at, next_run_at
            FROM project_rescan_settings
            WHERE project_id = :pid AND organization_id = :org
            """
        ),
        {"pid": project_id, "org": org_id},
    )
    record = row.fetchone()
    if record:
        return RescanSettingsResponse(
            project_id=record[0],
            enabled=record[1],
            frequency_hours=record[2],
            last_enqueued_at=record[3],
            next_run_at=record[4],
        )
    return RescanSettingsResponse(
        project_id=project_id,
        enabled=False,
        frequency_hours=settings.DEFAULT_RESCAN_FREQUENCY_HOURS,
    )


async def _upsert_rescan_setting(
    db: AsyncSession,
    project_id: int,
    org_id: int,
    enabled: bool,
    frequency_hours: int,
) -> RescanSettingsResponse:
    now = datetime.utcnow()
    next_run = now if enabled else None

    result = await db.execute(
        text(
            """
            INSERT INTO project_rescan_settings (
                project_id,
                organization_id,
                enabled,
                frequency_hours,
                last_enqueued_at,
                next_run_at
            )
            VALUES (:pid, :org, :enabled, :freq, NULL, :next_run)
            ON CONFLICT (project_id) DO UPDATE
            SET enabled = EXCLUDED.enabled,
                frequency_hours = EXCLUDED.frequency_hours,
                organization_id = EXCLUDED.organization_id,
                next_run_at = CASE
                                  WHEN EXCLUDED.enabled THEN EXCLUDED.next_run_at
                                  ELSE NULL
                              END,
                last_enqueued_at = CASE
                                       WHEN EXCLUDED.enabled THEN project_rescan_settings.last_enqueued_at
                                       ELSE NULL
                                   END,
                updated_at = NOW()
            RETURNING project_id, enabled, frequency_hours, last_enqueued_at, next_run_at
            """
        ),
        {
            "pid": project_id,
            "org": org_id,
            "enabled": enabled,
            "freq": frequency_hours,
            "next_run": next_run,
        },
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=500, detail="Failed to persist rescan configuration"
        )

    return RescanSettingsResponse(
        project_id=row[0],
        enabled=row[1],
        frequency_hours=row[2],
        last_enqueued_at=row[3],
        next_run_at=row[4],
    )


@router.get(
    "/{project_id}/rescan",
    response_model=RescanSettingsResponse,
    summary="Retrieve current rescan settings for a project",
)
async def get_rescan_settings(
    project_id: int,
    org_id: int = Depends(get_org_id_from_header),
    db: AsyncSession = Depends(db_session.get_db),
):
    await _assert_project_access(db, project_id, org_id)
    record = await _fetch_rescan_setting(db, project_id, org_id)
    return record


@router.patch(
    "/{project_id}/rescan",
    response_model=RescanSettingsResponse,
    summary="Update scheduled rescan settings for a project",
)
async def update_rescan_settings(
    project_id: int,
    payload: RescanSettingsRequest,
    org_id: int = Depends(get_org_id_from_header),
    db: AsyncSession = Depends(db_session.get_db),
):
    await _assert_project_access(db, project_id, org_id)
    record = await _upsert_rescan_setting(
        db,
        project_id=project_id,
        org_id=org_id,
        enabled=payload.enabled,
        frequency_hours=payload.frequency_hours,
    )
    await db.commit()
    return record


@router.patch(
    "/rescan/bulk",
    response_model=List[RescanSettingsResponse],
    summary="Bulk update rescan settings for multiple projects",
)
async def bulk_update_rescan_settings(
    payload: BulkRescanSettingsRequest,
    org_id: int = Depends(get_org_id_from_header),
    db: AsyncSession = Depends(db_session.get_db),
):
    responses: List[RescanSettingsResponse] = []
    for project_id in payload.project_ids:
        await _assert_project_access(db, project_id, org_id)
        record = await _upsert_rescan_setting(
            db,
            project_id=project_id,
            org_id=org_id,
            enabled=payload.enabled,
            frequency_hours=payload.frequency_hours,
        )
        responses.append(record)
    await db.commit()
    return responses
