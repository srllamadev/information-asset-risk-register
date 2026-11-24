import base64
import os
os.environ.setdefault("SAKURA_SECRET_KEY", "test-only-secret-key-with-32-characters")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
from pathlib import Path
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.db import Base
import app.main  # Register the application before importing its routers.
from app.imports import WorkbookInput, import_workbook, preview
from app.dashboard import dashboard
from app.models import Asset, AssetDependency, RiskAssessment, RiskScenario, SecurityControl, User

EXAMPLE = Path(__file__).resolve().parents[2] / 'ejemplo' / 'Inventario_Activos_AGETIC_Bolivia_Ejemplo.xlsx'

@pytest.mark.skipif(not EXAMPLE.exists(), reason='El libro de ejemplo del usuario no está disponible')
def test_preview_and_atomic_import_of_workbook(tmp_path):
    engine=create_engine(f'sqlite:///{tmp_path / "test.db"}')
    @event.listens_for(engine,'connect')
    def foreign_keys(connection,_): connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    data=WorkbookInput(content_base64=base64.b64encode(EXAMPLE.read_bytes()).decode())
    with Session(engine, expire_on_commit=False) as db:
        admin=User(username='admin',password_hash='unused',role='administrador');db.add(admin);db.commit()
        result=preview(data,user=admin,db=db)
        assert result['valid'] and result['counts']=={'Inventario':50,'Riesgos':18,'Controles':20}
        assert db.scalar(select(func.count()).select_from(Asset)) == 0
        def reject_control(*_):
            raise IntegrityError('INSERT', {}, Exception('simulación de fallo'))
        event.listen(SecurityControl, 'before_insert', reject_control)
        try:
            with pytest.raises(HTTPException): import_workbook(data,user=admin,db=db)
        finally:
            event.remove(SecurityControl, 'before_insert', reject_control)
        assert db.scalar(select(func.count()).select_from(Asset)) == 0
        assert db.scalar(select(func.count()).select_from(RiskScenario)) == 0
        result=import_workbook(data,user=admin,db=db)
        assert result['counts']['Inventario']==50
        assert db.scalar(select(func.count()).select_from(Asset))==50
        assert db.scalar(select(func.count()).select_from(RiskScenario))==18
        assert db.scalar(select(func.count()).select_from(SecurityControl))==20
        assert db.scalar(select(func.count()).select_from(AssetDependency))>0
        assessment=db.scalar(select(RiskAssessment).order_by(RiskAssessment.id))
        assert assessment.residual_likelihood is None and assessment.residual_impact is None
        assert assessment.source_assessed_date.isoformat()=='2026-11-11'
        assert db.scalar(select(SecurityControl).order_by(SecurityControl.id)).implementation_status=='Propuesto'
        summary=dashboard(unit_id=None,user=admin,db=db)
        assert summary['assets_total']==50 and summary['risks_total']==18 and summary['residual_pending']==18
        assert summary['inherent_levels']['crítico']==6 and summary['inherent_levels']['alto']==12
        assert not preview(data,user=admin,db=db)['valid']
        with pytest.raises(HTTPException): import_workbook(data,user=admin,db=db)
        assert db.scalar(select(func.count()).select_from(Asset))==50
