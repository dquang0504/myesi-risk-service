from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ComplianceRequest(BaseModel):
    project_name: str
    user_id: int
    standard: Optional[str] = "ISO_27001:2022"
    weight_override_id: Optional[int] = None
    trend_weeks: Optional[int] = 8


class ComplianceResponse(BaseModel):
    project: str
    compliance_score: int
    standards: Dict[str, str]
    summary: Dict[str, int]
    generated_at: datetime


class VulnSummaryRequest(BaseModel):
    project_name: str = Field(..., description="Project name")
    user_id: int = Field(..., description="User ID")


class VulnerabilityStats(BaseModel):
    severity: str
    count: int


class VulnSummaryResponse(BaseModel):
    project: str
    total_vulnerabilities: int
    stats_by_severity: List[VulnerabilityStats]
    most_vulnerable_components: Dict[str, int]
    generated_at: datetime


# --- Control Mapping model for compliance enrichment ---
class ControlMapping(BaseModel):
    sbom_id: str
    component_name: str
    component_version: str
    control_id: str
    control_title: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = "auto"
    notes: Optional[str] = None
    created_at: Optional[datetime] = None


# --- Compliance Weight model ---
class ComplianceWeight(BaseModel):
    id: Optional[int] = None
    standard: str
    scope_key: str
    title: Optional[str] = None
    category: Optional[str] = None
    weight: float
    applicable: Optional[bool] = True
    updated_at: Optional[datetime] = None
