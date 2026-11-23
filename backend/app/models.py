from datetime import datetime, timezone
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default="consulta")
    active: Mapped[bool] = mapped_column(default=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="activo")
    unit_id: Mapped[int | None] = mapped_column(ForeignKey("organizational_units.id", ondelete="RESTRICT"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    entity: Mapped[str] = mapped_column(String(80))
    entity_id: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class OrganizationalUnit(Base):
    __tablename__ = "organizational_units"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)

class AssetAssessment(Base):
    __tablename__ = "asset_assessments"
    __table_args__ = (CheckConstraint("confidentiality BETWEEN 1 AND 5", name="ck_asset_confidentiality"), CheckConstraint("integrity BETWEEN 1 AND 5", name="ck_asset_integrity"), CheckConstraint("availability BETWEEN 1 AND 5", name="ck_asset_availability"))
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    confidentiality: Mapped[int]
    integrity: Mapped[int]
    availability: Mapped[int]
    confidentiality_reason: Mapped[str] = mapped_column(Text)
    integrity_reason: Mapped[str] = mapped_column(Text)
    availability_reason: Mapped[str] = mapped_column(Text)
    assessor_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Threat(Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(100), default="")
    active: Mapped[bool] = mapped_column(default=True)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(100), default="")
    active: Mapped[bool] = mapped_column(default=True)

class RiskScenario(Base):
    __tablename__ = "risk_scenarios"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    threat_id: Mapped[int] = mapped_column(ForeignKey("threats.id", ondelete="RESTRICT"))
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"))
    event: Mapped[str] = mapped_column(Text)
    causes: Mapped[str] = mapped_column(Text)
    consequences: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(200))
    identified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    __table_args__ = tuple(CheckConstraint(f"{field} BETWEEN 1 AND 5", name=f"ck_risk_{field}") for field in ("inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact"))
    id: Mapped[int] = mapped_column(primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_scenarios.id", ondelete="RESTRICT"), index=True)
    inherent_likelihood: Mapped[int]
    inherent_impact: Mapped[int]
    residual_likelihood: Mapped[int]
    residual_impact: Mapped[int]
    existing_controls: Mapped[str] = mapped_column(Text)
    effectiveness: Mapped[str] = mapped_column(Text)
    justification: Mapped[str] = mapped_column(Text)
    methodology: Mapped[str] = mapped_column(Text)
    assessor_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
