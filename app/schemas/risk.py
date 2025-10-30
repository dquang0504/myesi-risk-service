from pydantic import BaseModel
from typing import List, Optional


class VulnerabilitySchema(BaseModel):
    vuln_id: Optional[str]
    severity: Optional[float]


class ComponentSchema(BaseModel):
    name: str
    version: str
    vulnerabilities: List[VulnerabilitySchema] = []


class RiskScoreSchema(BaseModel):
    component_name: str
    score: float
