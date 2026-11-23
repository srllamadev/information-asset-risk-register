"""Authenticated CSV reports for the records currently visible to permitted roles."""
import csv
import io
from typing import Literal
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from .db import get_db
from .main import current_user, require_role, risk_level
from .models import Asset, AuditLog, RiskAssessment, RiskScenario, User

router = APIRouter(prefix="/api/v1/reports")

def safe_cell(value):
    text = "" if value is None else str(value)
    # Spreadsheet programs may ignore leading whitespace and control characters.
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text

def export_csv(header, rows, delimiter):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=delimiter, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows([safe_cell(value) for value in row] for row in rows)
    return Response(content=stream.getvalue().encode("utf-8-sig"), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="reporte.csv"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

@router.get("/assets.csv")
def assets_report(separator: Literal["coma", "punto_coma"] = "coma", q: str = "", unit_id: int | None = None, status: str | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    query = select(Asset).order_by(Asset.id)
    if q:
        query = query.where(Asset.name.contains(q, autoescape=True) | Asset.code.contains(q, autoescape=True))
    if unit_id is not None:
        query = query.where(Asset.unit_id == unit_id)
    if status is not None:
        query = query.where(Asset.status == status)
    items = db.scalars(query).all()
    rows = [(x.id, x.code, x.name, x.description, x.status, x.unit_id, x.created_at.isoformat() + ("+00:00" if x.created_at.tzinfo is None else "")) for x in items]
    db.add(AuditLog(user_id=user.id, action="exportar", entity="activos", entity_id=""))
    db.commit()
    return export_csv(["ID", "Código", "Nombre", "Descripción", "Estado", "ID unidad", "Fecha de registro UTC"], rows, "," if separator == "coma" else ";")

@router.get("/risks.csv")
def risks_report(separator: Literal["coma", "punto_coma"] = "coma", asset_id: int | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador", "gestor", "auditor"})
    query = select(RiskScenario).order_by(RiskScenario.id)
    if asset_id is not None:
        query = query.where(RiskScenario.asset_id == asset_id)
    items = db.scalars(query).all()
    rows = []
    for risk in items:
        assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.risk_id == risk.id).order_by(RiskAssessment.id.desc()).limit(1))
        inherent = assessment.inherent_likelihood * assessment.inherent_impact if assessment else None
        residual = assessment.residual_likelihood * assessment.residual_impact if assessment else None
        rows.append((risk.id, risk.asset_id, risk.threat_id, risk.vulnerability_id, risk.event, risk.causes, risk.consequences, risk.owner, risk.identified_at.isoformat() + ("+00:00" if risk.identified_at.tzinfo is None else ""), inherent, risk_level(inherent) if inherent else "", residual, risk_level(residual) if residual else ""))
    db.add(AuditLog(user_id=user.id, action="exportar", entity="riesgos", entity_id=""))
    db.commit()
    return export_csv(["ID", "ID activo", "ID amenaza", "ID vulnerabilidad", "Evento", "Causas", "Consecuencias", "Propietario", "Fecha de identificación UTC", "Riesgo inherente", "Nivel inherente", "Riesgo residual", "Nivel residual"], rows, "," if separator == "coma" else ";")
