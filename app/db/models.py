from sqlalchemy import (
    Column,
    String,
    Integer,
    BigInteger,
    Text,
    TIMESTAMP,
    ForeignKey,
    UUID,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()


# SBOM table
class SBOM(Base):
    __tablename__ = "sboms"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_name = Column(String(255), nullable=False)
    source = Column(String(50), nullable=False)
    sbom = Column(JSONB, nullable=False)
    summary = Column(JSONB)
    object_url = Column(String(1024))
    created_at = Column(
        TIMESTAMP(timezone=True), server_default="now()", nullable=False
    )
    updated_at = Column(TIMESTAMP(timezone=True), server_default="now()")


# Vulnerabilities table
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False)
    project_name = Column(Text)
    component_name = Column(Text, nullable=False)
    component_version = Column(Text, nullable=False)
    vuln_id = Column(Text, nullable=True)  # optional
    severity = Column(Text)
    osv_metadata = Column(JSONB)
    cvss_vector = Column(String(255))
    sbom_component_count = Column(Integer, default=0)
    sbom_hash = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default="now()")
    updated_at = Column(TIMESTAMP(timezone=True), server_default="now()")


# Risk scores table (mới cho Risk Service)
class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"))
    component_name = Column(Text, nullable=False)
    component_version = Column(Text, nullable=False)
    score = Column(Integer)  # hoặc Float nếu muốn chi tiết
    created_at = Column(TIMESTAMP(timezone=True), server_default="now()")
