from sqlalchemy import (
    JSON,
    Column,
    String,
    Integer,
    BigInteger,
    Text,
    TIMESTAMP,
    ForeignKey,
    UUID,
    Boolean,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()


# User table
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(100), default="user")
    status = Column(String(50), default="active")
    is_active = Column(Integer, default=True)
    created_at = Column(TIMESTAMP, server_default="now()")
    last_login = Column(TIMESTAMP)


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
    fix_available = Column(Boolean, default=False)
    fixed_version = Column(Text)
    osv_metadata = Column(JSONB)
    cvss_vector = Column(String(255))
    sbom_component_count = Column(Integer, default=0)
    sbom_hash = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default="now()")
    updated_at = Column(TIMESTAMP(timezone=True), server_default="now()")


# Risk scores table
class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"))
    component_name = Column(Text, nullable=False)
    component_version = Column(Text, nullable=False)
    score = Column(Integer)  # hoặc Float nếu muốn chi tiết
    created_at = Column(TIMESTAMP(timezone=True), server_default="now()")


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"
    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id", ondelete="CASCADE"))
    project_name = Column(String)
    report_type = Column(String, default="compliance")
    report_data = Column(JSON)
    report_url = Column(String)
    generated_by = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="completed")
    created_at = Column(TIMESTAMP)
    updated_at = Column(TIMESTAMP)
