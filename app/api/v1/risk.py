from fastapi import APIRouter, Depends
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.db.models import Vulnerability
from app.db import session as db_session
from app.services.risk_service import (
    save_risk_scores,
    get_risk_trends,
)
from pydantic import BaseModel

router = APIRouter(prefix="/api/risk", tags=["Risk"])


class RiskScoreResponse(BaseModel):
    component_name: str
    component_version: str
    score: float


class RiskTrendResponse(BaseModel):
    component_name: str
    average_score: float
    sbom_count: int


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
