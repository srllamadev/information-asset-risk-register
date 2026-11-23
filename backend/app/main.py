import os
import hashlib
import time
import secrets
from datetime import date, datetime, timedelta, timezone
from typing import Literal
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .db import get_db
from .models import Asset, AssetCategory, AssetDependency, AssetAssessment, AuditLog, AuthSession, LoginAttempt, OrganizationalUnit, RiskAssessment, RiskScenario, Threat, User, Vulnerability

# No fallback secret: startup must fail when configuration is incomplete.
SECRET = os.environ.get("SAKURA_SECRET_KEY", "")
if len(SECRET) < 32:
    raise RuntimeError("SAKURA_SECRET_KEY debe contener al menos 32 caracteres")
docs_enabled = os.environ.get("SAKURA_ENABLE_DOCS") == "1"
app = FastAPI(title="Sakura Risk Manager", docs_url="/docs" if docs_enabled else None, redoc_url=None, openapi_url="/openapi.json" if docs_enabled else None)
bearer = HTTPBearer()
hasher = PasswordHasher()
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(32))

class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)

class AssetCreate(BaseModel):
    code: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    unit_id: int | None = None
    asset_type: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=150)
    subcategory: str | None = Field(default=None, max_length=150)
    process: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    custodian: str | None = Field(default=None, max_length=200)
    responsible: str | None = Field(default=None, max_length=200)
    location: str | None = Field(default=None, max_length=200)
    classification: str | None = Field(default=None, max_length=100)
    review_date: date | None = None
    observations: str | None = Field(default=None, max_length=10000)

class UTCResponse(BaseModel):
    @field_serializer("*", check_fields=False)
    def serialize_utc(self, value):
        if isinstance(value, datetime):
            return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()
        return value

class AssetRead(AssetCreate, UTCResponse):
    model_config = ConfigDict(from_attributes=True)
    id: int
    status: str
    created_at: datetime
    updated_at: datetime | None

def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET, algorithms=["HS256"], options={"require": ["exp", "sub", "jti"]})
        user = db.get(User, int(payload["sub"]))
        session = db.get(AuthSession, payload["jti"])
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(401, "Sesión inválida")
    if not user or not user.active or not session or session.revoked or session.user_id != user.id:
        raise HTTPException(401, "Sesión inválida")
    return user

@app.get("/api/v1/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/auth/login")
def login(data: Login, db: Session = Depends(get_db)):
    # Serialize reservation of an attempt so simultaneous requests cannot bypass the limit.
    attempt_key = hashlib.sha256(data.username.casefold().encode("utf-8")).hexdigest()
    now = int(time.time())
    db.execute(text("BEGIN IMMEDIATE"))
    db.execute(delete(LoginAttempt).where(LoginAttempt.window_started <= now - 900))
    attempt = db.get(LoginAttempt, attempt_key)
    if attempt is None:
        attempt = LoginAttempt(key=attempt_key, attempts=0, window_started=now)
        db.add(attempt)
    elif now - attempt.window_started >= 900:
        attempt.attempts, attempt.window_started = 0, now
    if attempt.attempts >= 5:
        db.commit()
        raise HTTPException(429, "Demasiados intentos; inténtelo más tarde", headers={"Retry-After": str(max(1, 900 - (now - attempt.window_started)))})
    attempt.attempts += 1
    db.commit()
    user = db.scalar(select(User).where(User.username == data.username))
    try:
        valid = hasher.verify(user.password_hash if user else DUMMY_HASH, data.password) and user is not None
    except (VerifyMismatchError, InvalidHashError):
        valid = False
    if not valid or not user.active:
        raise HTTPException(401, "Credenciales inválidas")
    attempt = db.get(LoginAttempt, attempt_key)
    if attempt is not None:
        db.delete(attempt)
    user.last_login = datetime.now(timezone.utc)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    session_id = secrets.token_hex(32)
    db.add(AuthSession(id=session_id, user_id=user.id, expires_at=expires_at))
    db.add(AuditLog(user_id=user.id, action="inicio_sesion", entity="usuario", entity_id=str(user.id)))
    db.commit()
    token = jwt.encode({"sub": str(user.id), "exp": expires_at, "jti": session_id}, SECRET, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "expires_in": 900}

@app.get("/api/v1/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}

@app.get("/api/v1/assets", response_model=list[AssetRead])
def list_assets(offset: int = 0, limit: int = 50, q: str = "", unit_id: int | None = None, status: str | None = None, category: str | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role not in {"administrador", "gestor", "auditor"}:
        raise HTTPException(403, "Acceso denegado")
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Paginación inválida")
    query = select(Asset)
    if q:
        query = query.where(Asset.name.contains(q, autoescape=True) | Asset.code.contains(q, autoescape=True))
    if unit_id is not None:
        query = query.where(Asset.unit_id == unit_id)
    if status is not None:
        query = query.where(Asset.status == status)
    if category:
        query = query.where(Asset.category == category)
    return db.scalars(query.order_by(Asset.id).offset(offset).limit(limit)).all()

def validated_asset_category(category: str | None, db: Session, previous: str | None = None) -> str | None:
    if category and category == previous:
        return previous
    name = category.strip() if category else None
    if name and name != previous:
        item = db.scalar(select(AssetCategory).where(AssetCategory.name == name, AssetCategory.active.is_(True)))
        if item is None:
            raise HTTPException(422, "Selecciona una categoría activa del catálogo")
    return name

@app.post("/api/v1/assets", response_model=AssetRead, status_code=201)
def create_asset(data: AssetCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role not in {"administrador", "gestor"}:
        raise HTTPException(403, "Acceso denegado")
    if data.unit_id is not None and not db.get(OrganizationalUnit, data.unit_id):
        raise HTTPException(422, "Unidad organizacional inexistente")
    values = data.model_dump()
    values["category"] = validated_asset_category(data.category, db)
    asset = Asset(**values)
    db.add(asset)
    try:
        db.flush()
        db.add(AuditLog(user_id=user.id, action="crear", entity="activo", entity_id=str(asset.id)))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El código ya existe")
    return asset

class UnitCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200, pattern=r".*\S.*")

class UnitRead(UnitCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int

class AssessmentCreate(BaseModel):
    confidentiality: int = Field(ge=1, le=5)
    integrity: int = Field(ge=1, le=5)
    availability: int = Field(ge=1, le=5)
    confidentiality_reason: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    integrity_reason: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    availability_reason: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")

class AssessmentRead(AssessmentCreate, UTCResponse):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int
    assessor_id: int
    assessed_at: datetime
    criticality: int

def require_role(user: User, roles: set[str]):
    if user.role not in roles:
        raise HTTPException(403, "Acceso denegado")

def assessment_read(item: AssetAssessment):
    return AssessmentRead.model_validate({**{key: getattr(item, key) for key in AssessmentCreate.model_fields}, "id": item.id, "asset_id": item.asset_id, "assessor_id": item.assessor_id, "assessed_at": item.assessed_at, "criticality": max(item.confidentiality, item.integrity, item.availability)})

@app.get("/api/v1/organizational-units", response_model=list[UnitRead])
def list_units(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    return db.scalars(select(OrganizationalUnit).order_by(OrganizationalUnit.name)).all()

@app.post("/api/v1/organizational-units", response_model=UnitRead, status_code=201)
def create_unit(data: UnitCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador"})
    unit = OrganizationalUnit(name=data.name.strip())
    db.add(unit)
    try:
        db.flush()
        db.add(AuditLog(user_id=user.id, action="crear", entity="unidad", entity_id=str(unit.id)))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "La unidad ya existe")
    return unit

@app.get("/api/v1/assets/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Activo no encontrado")
    return asset

@app.put("/api/v1/assets/{asset_id}", response_model=AssetRead)
def update_asset(asset_id: int, data: AssetCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor"})
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Activo no encontrado")
    if asset.status == "retirado":
        raise HTTPException(409, "El activo está retirado")
    if data.unit_id is not None and not db.get(OrganizationalUnit, data.unit_id):
        raise HTTPException(422, "Unidad organizacional inexistente")
    values = data.model_dump()
    values["category"] = validated_asset_category(data.category, db, asset.category)
    for key, value in values.items():
        setattr(asset, key, value)
    try:
        db.add(AuditLog(user_id=user.id, action="modificar", entity="activo", entity_id=str(asset.id)))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El código ya existe")
    return asset

@app.post("/api/v1/assets/{asset_id}/retire", response_model=AssetRead)
def retire_asset(asset_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor"})
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Activo no encontrado")
    if asset.status != "retirado":
        asset.status = "retirado"
        db.add(AuditLog(user_id=user.id, action="retirar", entity="activo", entity_id=str(asset.id)))
        db.commit()
    return asset

@app.post("/api/v1/assets/{asset_id}/assessments", response_model=AssessmentRead, status_code=201)
def create_assessment(asset_id: int, data: AssessmentCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor"})
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Activo no encontrado")
    if asset.status == "retirado":
        raise HTTPException(409, "El activo está retirado")
    assessment = AssetAssessment(asset_id=asset_id, assessor_id=user.id, **data.model_dump())
    db.add(assessment)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="valorar", entity="activo", entity_id=str(asset_id)))
    db.commit()
    return assessment_read(assessment)

@app.get("/api/v1/assets/{asset_id}/assessments", response_model=list[AssessmentRead])
def list_assessments(asset_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    if not db.get(Asset, asset_id):
        raise HTTPException(404, "Activo no encontrado")
    items = db.scalars(select(AssetAssessment).where(AssetAssessment.asset_id == asset_id).order_by(AssetAssessment.id.desc())).all()
    return [assessment_read(item) for item in items]

class CatalogCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200, pattern=r".*\S.*")
    description: str = Field(default="", max_length=5000)
    category: str = Field(default="", max_length=100)

class CatalogRead(CatalogCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    active: bool

class RiskCreate(BaseModel):
    asset_id: int
    threat_id: int
    vulnerability_id: int
    event: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    causes: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    consequences: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    owner: str = Field(min_length=1, max_length=200, pattern=r".*\S.*")

class RiskRead(RiskCreate, UTCResponse):
    model_config = ConfigDict(from_attributes=True)
    id: int
    identified_at: datetime

class RiskAssessmentCreate(BaseModel):
    inherent_likelihood: int = Field(ge=1, le=5)
    inherent_impact: int = Field(ge=1, le=5)
    residual_likelihood: int = Field(ge=1, le=5)
    residual_impact: int = Field(ge=1, le=5)
    existing_controls: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    effectiveness: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    justification: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")

class RiskAssessmentRead(RiskAssessmentCreate, UTCResponse):
    id: int
    risk_id: int
    assessor_id: int
    assessed_at: datetime
    methodology: str
    inherent_score: int
    inherent_level: str
    residual_score: int
    residual_level: str

METHODOLOGY_V1 = 'v1: probabilidad × impacto; 1-4 bajo, 5-9 medio, 10-16 alto, 17-25 crítico'

def risk_level(score: int) -> str:
    if score <= 4:
        return "bajo"
    if score <= 9:
        return "medio"
    if score <= 16:
        return "alto"
    return "crítico"

def risk_assessment_read(item: RiskAssessment):
    inherent = item.inherent_likelihood * item.inherent_impact
    residual = item.residual_likelihood * item.residual_impact
    return RiskAssessmentRead(**{key: getattr(item, key) for key in RiskAssessmentCreate.model_fields}, id=item.id, risk_id=item.risk_id, assessor_id=item.assessor_id, assessed_at=item.assessed_at, methodology=item.methodology, inherent_score=inherent, inherent_level=risk_level(inherent), residual_score=residual, residual_level=risk_level(residual))

def install_catalog_routes(path: str, model):
    def list_catalog(user: User = Depends(current_user), db: Session = Depends(get_db)):
        require_role(user, {"administrador", "gestor", "auditor"})
        return db.scalars(select(model).order_by(model.name)).all()
    def create_catalog(data: CatalogCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
        require_role(user, {"administrador", "gestor"})
        item = model(**data.model_dump())
        db.add(item)
        try:
            db.flush()
            db.add(AuditLog(user_id=user.id, action="crear", entity=path, entity_id=str(item.id)))
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "El nombre ya existe")
        return item
    app.add_api_route(f"/api/v1/{path}", list_catalog, methods=["GET"], response_model=list[CatalogRead], name=f"list_{path}")
    app.add_api_route(f"/api/v1/{path}", create_catalog, methods=["POST"], response_model=CatalogRead, status_code=201, name=f"create_{path}")

install_catalog_routes("threats", Threat)
install_catalog_routes("vulnerabilities", Vulnerability)

@app.post("/api/v1/risks", response_model=RiskRead, status_code=201)
def create_risk(data: RiskCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor"})
    asset = db.get(Asset, data.asset_id)
    threat = db.get(Threat, data.threat_id)
    vulnerability = db.get(Vulnerability, data.vulnerability_id)
    if not asset or not threat or not vulnerability:
        raise HTTPException(422, "Activo, amenaza o vulnerabilidad inexistente")
    if asset.status == "retirado" or not threat.active or not vulnerability.active:
        raise HTTPException(409, "Los elementos relacionados deben estar activos")
    item = RiskScenario(**data.model_dump())
    db.add(item)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="crear", entity="riesgo", entity_id=str(item.id)))
    db.commit()
    return item

@app.get("/api/v1/risks", response_model=list[RiskRead])
def list_risks(offset: int = 0, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Paginación inválida")
    return db.scalars(select(RiskScenario).order_by(RiskScenario.id).offset(offset).limit(limit)).all()

@app.post("/api/v1/risks/{risk_id}/assessments", response_model=RiskAssessmentRead, status_code=201)
def create_risk_assessment(risk_id: int, data: RiskAssessmentCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor"})
    if not db.get(RiskScenario, risk_id):
        raise HTTPException(404, "Riesgo no encontrado")
    item = RiskAssessment(risk_id=risk_id, assessor_id=user.id, methodology=METHODOLOGY_V1, **data.model_dump())
    db.add(item)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="evaluar", entity="riesgo", entity_id=str(risk_id)))
    db.commit()
    return risk_assessment_read(item)

@app.get("/api/v1/risks/{risk_id}/assessments", response_model=list[RiskAssessmentRead])
def list_risk_assessments(risk_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    if not db.get(RiskScenario, risk_id):
        raise HTTPException(404, "Riesgo no encontrado")
    items = db.scalars(select(RiskAssessment).where(RiskAssessment.risk_id == risk_id).order_by(RiskAssessment.id.desc())).all()
    return [risk_assessment_read(item) for item in items]

# Routes are registered after the shared authentication dependencies are defined.
from .treatments import router as treatments_router
app.include_router(treatments_router)
from .reports import router as reports_router
app.include_router(reports_router)

class AuditRead(UTCResponse):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_id: int | None
    action: str
    entity: str
    entity_id: str
    created_at: datetime

@app.get("/api/v1/audit-logs", response_model=list[AuditRead])
def list_audit_logs(offset: int = 0, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "auditor"})
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Paginación inválida")
    return db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(limit)).all()

from .users import router as users_router
app.include_router(users_router)

from .matrix import router as matrix_router
app.include_router(matrix_router)

class DependencyInput(BaseModel):
    depends_on_id: int = Field(gt=0)

@app.get('/api/v1/assets/{asset_id}/dependencies', response_model=list[AssetRead])
def list_asset_dependencies(asset_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador', 'gestor', 'auditor'})
    if not db.get(Asset, asset_id):
        raise HTTPException(404, 'Activo no encontrado')
    return db.scalars(select(Asset).join(AssetDependency, AssetDependency.depends_on_id == Asset.id).where(AssetDependency.asset_id == asset_id).order_by(Asset.code)).all()

@app.post('/api/v1/assets/{asset_id}/dependencies', status_code=201)
def add_asset_dependency(asset_id: int, data: DependencyInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador', 'gestor'})
    asset = db.get(Asset, asset_id)
    target = db.get(Asset, data.depends_on_id)
    if not asset or not target:
        raise HTTPException(404, 'Activo no encontrado')
    if asset.id == target.id:
        raise HTTPException(422, 'Un activo no puede depender de sí mismo')
    if asset.status == 'retirado' or target.status == 'retirado':
        raise HTTPException(409, 'No se pueden vincular activos retirados')
    if db.get(AssetDependency, (asset.id, target.id)):
        raise HTTPException(409, 'La dependencia ya existe')
    db.add(AssetDependency(asset_id=asset.id, depends_on_id=target.id))
    db.add(AuditLog(user_id=user.id, action='vincular_dependencia', entity='activo', entity_id=str(asset.id)))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'No se pudo guardar la dependencia')
    return {'asset_id': asset.id, 'depends_on_id': target.id}

@app.delete('/api/v1/assets/{asset_id}/dependencies/{depends_on_id}', status_code=204)
def remove_asset_dependency(asset_id: int, depends_on_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador', 'gestor'})
    dependency = db.get(AssetDependency, (asset_id, depends_on_id))
    if not dependency:
        raise HTTPException(404, 'Dependencia no encontrada')
    db.delete(dependency)
    db.add(AuditLog(user_id=user.id, action='desvincular_dependencia', entity='activo', entity_id=str(asset_id)))
    db.commit()

class AssetStatusInput(BaseModel):
    status: Literal['activo', 'en_revision', 'inactivo']

@app.put('/api/v1/assets/{asset_id}/status', response_model=AssetRead)
def change_asset_status(asset_id: int, data: AssetStatusInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador', 'gestor'})
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, 'Activo no encontrado')
    if asset.status == 'retirado':
        raise HTTPException(409, 'No se puede cambiar el estado de un activo retirado')
    if asset.status != data.status:
        asset.status = data.status
        db.add(AuditLog(user_id=user.id, action='cambiar_estado', entity='activo', entity_id=str(asset.id)))
        db.commit()
    return asset

class AssetCategoryInput(BaseModel):
    name: str = Field(min_length=1, max_length=150, pattern=r'.*\S.*')
    active: bool = True

class AssetCategoryRead(AssetCategoryInput):
    model_config = ConfigDict(from_attributes=True)
    id: int

@app.get('/api/v1/asset-categories', response_model=list[AssetCategoryRead])
def list_asset_categories(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador', 'gestor', 'auditor'})
    return db.scalars(select(AssetCategory).order_by(AssetCategory.name)).all()

@app.post('/api/v1/asset-categories', response_model=AssetCategoryRead, status_code=201)
def create_asset_category(data: AssetCategoryInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador'})
    item = AssetCategory(name=data.name.strip(), active=data.active)
    db.add(item)
    try:
        db.flush()
        db.add(AuditLog(user_id=user.id, action='crear', entity='categoria_activo', entity_id=str(item.id)))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'La categoría ya existe')
    return item

@app.put('/api/v1/asset-categories/{category_id}', response_model=AssetCategoryRead)
def update_asset_category(category_id: int, data: AssetCategoryInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador'})
    db.execute(text('BEGIN IMMEDIATE'))
    db.refresh(user)
    require_role(user, {'administrador'})
    if not user.active:
        raise HTTPException(403, 'Acceso denegado')
    item = db.get(AssetCategory, category_id)
    if not item:
        raise HTTPException(404, 'Categoría no encontrada')
    name = data.name.strip()
    if item.name == name and item.active == data.active:
        return item
    previous = item.name
    item.name, item.active = name, data.active
    try:
        db.flush()
        if previous != name:
            db.execute(update(Asset).where(Asset.category == previous).values(category=name, updated_at=datetime.now(timezone.utc)))
        db.add(AuditLog(user_id=user.id, action='modificar', entity='categoria_activo', entity_id=str(item.id)))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'La categoría ya existe')
    return item
