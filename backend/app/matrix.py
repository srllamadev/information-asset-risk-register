"""Latest risk evaluations for the risk matrix."""
from datetime import date, datetime, time, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .db import get_db
from .main import current_user, require_role
from .models import Asset, RiskAssessment, RiskScenario, User

router = APIRouter(prefix="/api/v1")

@router.get('/risk-matrix')
def risk_matrix(unit_id: int | None = None, asset_id: int | None = None, owner: str | None = None, date_from: date | None = None, date_to: date | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    if date_from and date_to and date_to < date_from:
        raise HTTPException(422, "La fecha final no puede ser anterior a la inicial")
    latest = select(RiskAssessment.risk_id, func.max(RiskAssessment.id).label('id')).group_by(RiskAssessment.risk_id).subquery()
    query = select(RiskScenario, RiskAssessment).join(latest, latest.c.risk_id == RiskScenario.id).join(RiskAssessment, RiskAssessment.id == latest.c.id).join(Asset, Asset.id == RiskScenario.asset_id)
    if unit_id is not None:
        query = query.where(Asset.unit_id == unit_id)
    if asset_id is not None:
        query = query.where(RiskScenario.asset_id == asset_id)
    if owner:
        query = query.where(RiskScenario.owner.contains(owner, autoescape=True))
    if date_from:
        query = query.where(RiskAssessment.assessed_at >= datetime.combine(date_from, time.min, tzinfo=timezone.utc))
    if date_to:
        if date_to == date.max:
            query = query.where(RiskAssessment.assessed_at <= datetime.max.replace(tzinfo=timezone.utc))
        else:
            query = query.where(RiskAssessment.assessed_at < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=timezone.utc))
    rows = db.execute(query.order_by(RiskScenario.id)).all()
    return [{"risk_id": r.id, "event": r.event, "asset_id": r.asset_id, "owner": r.owner, "assessment_id": a.id, "assessed_at": (a.assessed_at.replace(tzinfo=timezone.utc) if a.assessed_at.tzinfo is None else a.assessed_at.astimezone(timezone.utc)).isoformat(), "inherent_likelihood": a.inherent_likelihood, "inherent_impact": a.inherent_impact, "residual_likelihood": a.residual_likelihood, "residual_impact": a.residual_impact} for r,a in rows]
