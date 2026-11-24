"""Dashboard aggregations from persisted records, without page limits."""
from collections import Counter
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .db import get_db
from .main import current_user, require_role, risk_level
from .models import Asset, AssetAssessment, OrganizationalUnit, RiskScenario, RiskAssessment, RiskControl, RiskTreatment, SecurityControl, TreatmentControl, User

router=APIRouter(prefix='/api/v1')

@router.get('/dashboard')
def dashboard(unit_id: int | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {'administrador','gestor','auditor'})
    aq=select(Asset)
    rq=select(RiskScenario).join(Asset, Asset.id==RiskScenario.asset_id)
    if unit_id is not None:
        aq=aq.where(Asset.unit_id==unit_id)
        rq=rq.where(Asset.unit_id==unit_id)
    assets=db.scalars(aq).all()
    risks=db.scalars(rq).all()
    risk_ids={r.id for r in risks}
    asset_ids={a.id for a in assets}
    latest=select(RiskAssessment.risk_id,func.max(RiskAssessment.id).label('latest')).group_by(RiskAssessment.risk_id).subquery()
    evaluations=db.scalars(select(RiskAssessment).join(latest, RiskAssessment.id==latest.c.latest)).all()
    evaluations=[e for e in evaluations if e.risk_id in risk_ids]
    asset_latest=select(AssetAssessment.asset_id,func.max(AssetAssessment.id).label('latest')).group_by(AssetAssessment.asset_id).subquery()
    asset_assessments=db.scalars(select(AssetAssessment).join(asset_latest,AssetAssessment.id==asset_latest.c.latest)).all()
    asset_assessments=[e for e in asset_assessments if e.asset_id in asset_ids]
    treatments=db.scalars(select(RiskTreatment)).all()
    treatments=[t for t in treatments if t.risk_id in risk_ids]
    levels=Counter(risk_level(e.inherent_likelihood*e.inherent_impact) for e in evaluations)
    residual=Counter(risk_level(e.residual_likelihood*e.residual_impact) for e in evaluations if e.residual_likelihood is not None and e.residual_impact is not None)
    units={x.id:x.name for x in db.scalars(select(OrganizationalUnit)).all()}
    categories=Counter(a.category or 'Sin categoría' for a in assets)
    by_unit=Counter(units.get(a.unit_id,'Sin unidad') for a in assets)
    status=Counter(t.status for t in treatments)
    today=datetime.now(timezone.utc).date().isoformat()
    if unit_id is None:
        controls=db.scalars(select(SecurityControl)).all()
    else:
        direct = select(RiskControl.control_id).join(RiskScenario, RiskScenario.id==RiskControl.risk_id).join(Asset, Asset.id==RiskScenario.asset_id).where(Asset.unit_id==unit_id)
        through_treatment = select(TreatmentControl.control_id).join(RiskTreatment, RiskTreatment.id==TreatmentControl.treatment_id).join(RiskScenario, RiskScenario.id==RiskTreatment.risk_id).join(Asset, Asset.id==RiskScenario.asset_id).where(Asset.unit_id==unit_id)
        controls=db.scalars(select(SecurityControl).where(SecurityControl.id.in_(direct.union(through_treatment)))).all()
    controls_by_status=Counter((c.implementation_status or 'Sin estado') for c in controls)
    return {'assets_total':len(assets),'assets_critical':sum(max(a.confidentiality,a.integrity,a.availability)>=4 for a in asset_assessments),'asset_criticality_note':'Propuesta: valor CIA máximo 4 o 5; pendiente de configuración institucional.', 'assets_unassessed':len(assets)-len(asset_assessments), 'risks_total':len(risks),'risks_unassessed':len(risks)-len(evaluations),'residual_pending':sum(e.residual_likelihood is None for e in evaluations),'inherent_levels':{level:levels[level] for level in ('bajo','medio','alto','crítico')},'residual_levels':{level:residual[level] for level in ('bajo','medio','alto','crítico')},'assets_by_category':[{'name':k,'count':v} for k,v in sorted(categories.items())], 'assets_by_unit':[{'name':k,'count':v} for k,v in sorted(by_unit.items())], 'treatments_by_status':dict(status), 'risks_without_treatment':len(risk_ids-{t.risk_id for t in treatments}), 'controls_total':len(controls), 'controls_by_status':dict(controls_by_status), 'treatments_overdue':sum(t.target_date < today and t.status not in {'implementado','verificado','cerrado'} for t in treatments)}
