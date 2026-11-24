from datetime import date, datetime, timezone
from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, String, Text
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
    macroprocess: Mapped[str | None] = mapped_column(String(200), nullable=True)
    subprocess: Mapped[str | None] = mapped_column(String(200), nullable=True)
    administrator: Mapped[str | None] = mapped_column(String(200), nullable=True)
    authorized_users: Mapped[str | None] = mapped_column(Text, nullable=True)
    supplier: Mapped[str | None] = mapped_column(String(200), nullable=True)
    criticality_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_status: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    normative_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    asset_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    category: Mapped[str | None] = mapped_column(String(150), nullable=True)
    subcategory: Mapped[str | None] = mapped_column(String(150), nullable=True)
    process: Mapped[str | None] = mapped_column(String(200), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    custodian: Mapped[str | None] = mapped_column(String(200), nullable=True)
    responsible: Mapped[str | None] = mapped_column(String(200), nullable=True)
    location: Mapped[str | None] = mapped_column(String(200), nullable=True)
    classification: Mapped[str | None] = mapped_column(String(100), nullable=True)
    review_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    observations: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class AssetDependency(Base):
    __tablename__ = "asset_dependencies"
    __table_args__ = (CheckConstraint("asset_id != depends_on_id", name="ck_asset_dependency_not_self"),)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), primary_key=True)
    depends_on_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), primary_key=True)

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
    code: Mapped[str | None] = mapped_column(String(80), unique=True, index=True, nullable=True)
    affected_process: Mapped[str | None] = mapped_column(String(200), nullable=True)
    evidence_status: Mapped[str | None] = mapped_column(String(100), nullable=True)
    evidence_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    proposed_treatment: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    __table_args__ = tuple(CheckConstraint(f"{field} BETWEEN 1 AND 5", name=f"ck_risk_{field}") for field in ("inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact")) + (CheckConstraint("(residual_likelihood IS NULL AND residual_impact IS NULL) OR (residual_likelihood IS NOT NULL AND residual_impact IS NOT NULL)", name="ck_risk_residual_pair"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_scenarios.id", ondelete="RESTRICT"), index=True)
    inherent_likelihood: Mapped[int]
    inherent_impact: Mapped[int]
    residual_likelihood: Mapped[int | None] = mapped_column(nullable=True)
    residual_impact: Mapped[int | None] = mapped_column(nullable=True)
    existing_controls: Mapped[str] = mapped_column(Text)
    effectiveness: Mapped[str] = mapped_column(Text)
    justification: Mapped[str] = mapped_column(Text)
    methodology: Mapped[str] = mapped_column(Text)
    source_assessed_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    assessor_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class SecurityControl(Base):
    __tablename__ = "security_controls"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(200), default="")
    reference: Mapped[str] = mapped_column(String(200), default="")
    control_type: Mapped[str] = mapped_column(String(100), default="")
    implementation_status: Mapped[str] = mapped_column(String(100), default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    review_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    implementation_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    verification_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    verified_effectiveness: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verification_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    observations: Mapped[str | None] = mapped_column(Text, nullable=True)

class RiskTreatment(Base):
    __tablename__ = "risk_treatments"
    id: Mapped[int] = mapped_column(primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_scenarios.id", ondelete="RESTRICT"), index=True)
    strategy: Mapped[str] = mapped_column(String(20))
    description: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(200))
    start_date: Mapped[str] = mapped_column(String(10))
    target_date: Mapped[str] = mapped_column(String(10))
    priority: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    evidence: Mapped[str] = mapped_column(Text, default="")
    observations: Mapped[str] = mapped_column(Text, default="")
    acceptance_authority: Mapped[str] = mapped_column(String(200), default="")
    acceptance_justification: Mapped[str] = mapped_column(Text, default="")
    acceptance_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    acceptance_review_date: Mapped[str | None] = mapped_column(String(10), nullable=True)

class RiskControl(Base):
    __tablename__ = "risk_controls"
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_scenarios.id", ondelete="RESTRICT"), primary_key=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("security_controls.id", ondelete="RESTRICT"), primary_key=True)

class TreatmentControl(Base):
    __tablename__ = "treatment_controls"
    treatment_id: Mapped[int] = mapped_column(ForeignKey("risk_treatments.id", ondelete="RESTRICT"), primary_key=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("security_controls.id", ondelete="RESTRICT"), primary_key=True)

class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked: Mapped[bool] = mapped_column(default=False)

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(default=0)
    window_started: Mapped[int]

class AssetCategory(Base):
    __tablename__ = "asset_categories"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    active: Mapped[bool] = mapped_column(default=True)
