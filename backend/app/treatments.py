"""Control catalog and risk treatment endpoints."""
from datetime import date, datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .db import get_db
from .main import current_user, require_role
from .models import AuditLog, RiskControl, RiskScenario, RiskTreatment, SecurityControl, TreatmentControl, User

router = APIRouter(prefix="/api/v1")
READ = {"administrador", "gestor", "auditor"}
WRITE = {"administrador", "gestor"}

class ControlInput(BaseModel):
    code: str = Field(min_length=1, max_length=80, pattern=r".*\S.*")
    name: str = Field(min_length=1, max_length=200, pattern=r".*\S.*")
    description: str = Field(default="", max_length=5000)
    source: str = Field(default="", max_length=200)
    reference: str = Field(default="", max_length=200)
    control_type: str = Field(default="", max_length=100)
    implementation_status: str = Field(default="", max_length=100)
    owner: str = Field(default="", max_length=200)
    evidence: str = Field(default="", max_length=5000)
    review_date: date | None = None
    implementation_date: date | None = None
    verification_date: date | None = None
    verified_effectiveness: str | None = Field(default=None, max_length=100)
    verification_result: str | None = Field(default=None, max_length=5000)
    observations: str | None = Field(default=None, max_length=5000)

class ControlRead(ControlInput):
    model_config = ConfigDict(from_attributes=True)
    id: int

class TreatmentInput(BaseModel):
    risk_id: int
    strategy: Literal["mitigar", "evitar", "transferir", "aceptar"]
    description: str = Field(min_length=1, max_length=5000, pattern=r".*\S.*")
    owner: str = Field(min_length=1, max_length=200, pattern=r".*\S.*")
    start_date: date
    target_date: date
    priority: Literal["baja", "media", "alta", "critica"]
    status: Literal["pendiente", "en_proceso", "implementado", "verificado", "cerrado"]
    evidence: str = Field(default="", max_length=5000)
    observations: str = Field(default="", max_length=5000)
    acceptance_authority: str = Field(default="", max_length=200)
    acceptance_justification: str = Field(default="", max_length=5000)
    acceptance_date: date | None = None
    acceptance_review_date: date | None = None

    @model_validator(mode="after")
    def validate_dates_and_acceptance(self):
        if self.target_date < self.start_date:
            raise ValueError("La fecha objetivo no puede ser anterior al inicio")
        if self.strategy == "aceptar":
            if not self.acceptance_authority.strip() or not self.acceptance_justification.strip() or not self.acceptance_date or not self.acceptance_review_date:
                raise ValueError("La aceptación requiere autoridad, justificación, fecha y revisión")
            if self.acceptance_review_date < self.acceptance_date:
                raise ValueError("La revisión no puede ser anterior a la aceptación")
        elif self.acceptance_authority or self.acceptance_justification or self.acceptance_date or self.acceptance_review_date:
            raise ValueError("Los datos de aceptación solo corresponden a la estrategia aceptar")
        return self

class TreatmentRead(TreatmentInput):
    model_config = ConfigDict(from_attributes=True)
    id: int
    overdue: bool

class LinkInput(BaseModel):
    control_id: int

def db_values(data: BaseModel):
    values = data.model_dump()
    return {key: value.isoformat() if isinstance(value, date) else value for key, value in values.items()}

def read_treatment(item: RiskTreatment):
    values = {key: getattr(item, key) for key in TreatmentInput.model_fields}
    return TreatmentRead(**values, id=item.id, overdue=item.status not in {"implementado", "verificado", "cerrado"} and date.fromisoformat(item.target_date) < datetime.now(timezone.utc).date())

def log(db: Session, user: User, action: str, entity: str, entity_id: int):
    db.add(AuditLog(user_id=user.id, action=action, entity=entity, entity_id=str(entity_id)))

@router.get("/controls", response_model=list[ControlRead])
def list_controls(offset: int = 0, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, READ)
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Paginación inválida")
    return db.scalars(select(SecurityControl).order_by(SecurityControl.id).offset(offset).limit(limit)).all()

@router.post("/controls", response_model=ControlRead, status_code=201)
def create_control(data: ControlInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, WRITE)
    item = SecurityControl(**db_values(data))
    db.add(item)
    try:
        db.flush()
        log(db, user, "crear", "control", item.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El código de control ya existe")
    return item

@router.put("/controls/{control_id}", response_model=ControlRead)
def update_control(control_id: int, data: ControlInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, WRITE)
    item = db.get(SecurityControl, control_id)
    if not item:
        raise HTTPException(404, "Control no encontrado")
    for key, value in db_values(data).items():
        setattr(item, key, value)
    try:
        log(db, user, "modificar", "control", item.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El código de control ya existe")
    return item

@router.get("/risk-treatments", response_model=list[TreatmentRead])
def list_treatments(risk_id: int | None = None, offset: int = 0, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, READ)
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Paginación inválida")
    query = select(RiskTreatment)
    if risk_id is not None:
        query = query.where(RiskTreatment.risk_id == risk_id)
    return [read_treatment(item) for item in db.scalars(query.order_by(RiskTreatment.id).offset(offset).limit(limit)).all()]

@router.post("/risk-treatments", response_model=TreatmentRead, status_code=201)
def create_treatment(data: TreatmentInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, WRITE)
    if not db.get(RiskScenario, data.risk_id):
        raise HTTPException(422, "Riesgo inexistente")
    item = RiskTreatment(**db_values(data))
    db.add(item)
    db.flush()
    log(db, user, "crear", "tratamiento", item.id)
    db.commit()
    return read_treatment(item)

@router.put("/risk-treatments/{treatment_id}", response_model=TreatmentRead)
def update_treatment(treatment_id: int, data: TreatmentInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, WRITE)
    item = db.get(RiskTreatment, treatment_id)
    if not item:
        raise HTTPException(404, "Tratamiento no encontrado")
    if item.risk_id != data.risk_id:
        raise HTTPException(422, "No se puede cambiar el riesgo del tratamiento")
    for key, value in db_values(data).items():
        setattr(item, key, value)
    log(db, user, "modificar", "tratamiento", item.id)
    db.commit()
    return read_treatment(item)

@router.post("/risks/{risk_id}/controls", status_code=201)
def link_risk_control(risk_id: int, data: LinkInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, WRITE)
    if not db.get(RiskScenario, risk_id) or not db.get(SecurityControl, data.control_id):
        raise HTTPException(404, "Riesgo o control no encontrado")
    if db.get(RiskControl, (risk_id, data.control_id)):
        raise HTTPException(409, "El control ya está vinculado")
    db.add(RiskControl(risk_id=risk_id, control_id=data.control_id))
    log(db, user, "vincular_control", "riesgo", risk_id)
    db.commit()
    return {"risk_id": risk_id, "control_id": data.control_id}

@router.get("/risks/{risk_id}/controls", response_model=list[ControlRead])
def risk_controls(risk_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, READ)
    if not db.get(RiskScenario, risk_id):
        raise HTTPException(404, "Riesgo no encontrado")
    return db.scalars(select(SecurityControl).join(RiskControl).where(RiskControl.risk_id == risk_id)).all()

@router.post("/risk-treatments/{treatment_id}/controls", status_code=201)
def link_treatment_control(treatment_id: int, data: LinkInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, WRITE)
    if not db.get(RiskTreatment, treatment_id) or not db.get(SecurityControl, data.control_id):
        raise HTTPException(404, "Tratamiento o control no encontrado")
    if db.get(TreatmentControl, (treatment_id, data.control_id)):
        raise HTTPException(409, "El control ya está vinculado")
    db.add(TreatmentControl(treatment_id=treatment_id, control_id=data.control_id))
    log(db, user, "vincular_control", "tratamiento", treatment_id)
    db.commit()
    return {"treatment_id": treatment_id, "control_id": data.control_id}

@router.get("/risk-treatments/{treatment_id}/controls", response_model=list[ControlRead])
def treatment_controls(treatment_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, READ)
    if not db.get(RiskTreatment, treatment_id):
        raise HTTPException(404, "Tratamiento no encontrado")
    return db.scalars(select(SecurityControl).join(TreatmentControl).where(TreatmentControl.treatment_id == treatment_id)).all()
