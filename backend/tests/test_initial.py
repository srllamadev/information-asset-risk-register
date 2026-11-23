import asyncio
import csv
import io
import os
os.environ['SAKURA_SECRET_KEY'] = 'test-only-secret-key-with-32-characters'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

import httpx
from argon2 import PasswordHasher
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
from app.main import app
from app.models import User


def test_asset_workflow():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    @event.listens_for(engine, 'connect')
    def foreign_keys(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions() as db:
        db.add_all([User(username='admin', password_hash=PasswordHasher().hash('test-password'), role='administrador'), User(username='audit', password_hash=PasswordHasher().hash('test-password'), role='auditor')])
        db.commit()
    def override():
        with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = override
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            assert (await client.get('/api/v1/assets')).status_code == 403
            for _ in range(5):
                assert (await client.post('/api/v1/auth/login', json={'username':'desconocido','password':'incorrecta'})).status_code == 401
            blocked = await client.post('/api/v1/auth/login', json={'username':'desconocido','password':'incorrecta'})
            assert blocked.status_code == 429 and int(blocked.headers['Retry-After']) > 0
            assert (await client.post('/api/v1/auth/login', json={'username':'admin','password':'wrong'})).status_code == 401
            token = (await client.post('/api/v1/auth/login', json={'username':'admin','password':'test-password'})).json()['access_token']
            headers = {'Authorization': 'Bearer ' + token}
            unit = await client.post('/api/v1/organizational-units', json={'name':'Tecnología'}, headers=headers)
            assert unit.status_code == 201
            asset = {'code':'A-1','name':'Servidor','unit_id':unit.json()['id']}
            created = await client.post('/api/v1/assets', json=asset, headers=headers)
            assert created.status_code == 201
            asset_id = created.json()['id']
            assert len((await client.get('/api/v1/assets', params={'q':'Servidor', 'unit_id':unit.json()['id']}, headers=headers)).json()) == 1
            assert (await client.get('/api/v1/assets', params={'q':'inexistente'}, headers=headers)).json() == []
            assert (await client.post('/api/v1/assets', json=asset, headers=headers)).status_code == 409
            values = {'confidentiality':2, 'integrity':4, 'availability':5, 'confidentiality_reason':'Datos internos', 'integrity_reason':'Impacto alto', 'availability_reason':'Servicio crítico'}
            result = await client.post(f'/api/v1/assets/{asset_id}/assessments', json=values, headers=headers)
            assert result.status_code == 201 and result.json()['criticality'] == 5
            values['availability'] = 3
            assert (await client.post(f'/api/v1/assets/{asset_id}/assessments', json=values, headers=headers)).json()['criticality'] == 4
            assert len((await client.get(f'/api/v1/assets/{asset_id}/assessments', headers=headers)).json()) == 2
            values['availability'] = 6
            assert (await client.post(f'/api/v1/assets/{asset_id}/assessments', json=values, headers=headers)).status_code == 422
            threat = await client.post('/api/v1/threats', json={'name':'Malware'}, headers=headers)
            vulnerability = await client.post('/api/v1/vulnerabilities', json={'name':'Sin actualizaciones'}, headers=headers)
            assert threat.status_code == vulnerability.status_code == 201
            scenario = {'asset_id':asset_id, 'threat_id':threat.json()['id'], 'vulnerability_id':vulnerability.json()['id'], 'event':'Infección', 'causes':'Software vulnerable', 'consequences':'Interrupción', 'owner':'Tecnología'}
            risk = await client.post('/api/v1/risks', json=scenario, headers=headers)
            assert risk.status_code == 201
            risk_id = risk.json()['id']
            evaluation = {'inherent_likelihood':5, 'inherent_impact':4, 'residual_likelihood':2, 'residual_impact':3, 'existing_controls':'Actualizaciones', 'effectiveness':'Parcial', 'justification':'Análisis documentado'}
            response = await client.post(f'/api/v1/risks/{risk_id}/assessments', json=evaluation, headers=headers)
            assert response.status_code == 201
            assert (response.json()['inherent_score'], response.json()['inherent_level']) == (20, 'crítico')
            assert (response.json()['residual_score'], response.json()['residual_level']) == (6, 'medio')
            evaluation['residual_likelihood'] = 1
            assert (await client.post(f'/api/v1/risks/{risk_id}/assessments', json=evaluation, headers=headers)).status_code == 201
            assert len((await client.get(f'/api/v1/risks/{risk_id}/assessments', headers=headers)).json()) == 2
            matrix = await client.get('/api/v1/risk-matrix', params={'unit_id':unit.json()['id']}, headers=headers)
            assert matrix.status_code == 200 and len(matrix.json()) == 1
            assert matrix.json()[0]['residual_likelihood'] == 1
            assert (await client.get('/api/v1/risk-matrix', params={'unit_id':999}, headers=headers)).json() == []
            assert (await client.get('/api/v1/risk-matrix', params={'date_from':'2025-01-01', 'date_to':'2024-01-01'}, headers=headers)).status_code == 422
            control = await client.post('/api/v1/controls', json={'code':'CTL-1', 'name':'Copias de seguridad'}, headers=headers)
            assert control.status_code == 201
            control_id = control.json()['id']
            assert (await client.post('/api/v1/controls', json={'code':'CTL-1', 'name':'Duplicado'}, headers=headers)).status_code == 409
            treatment = {'risk_id':risk_id, 'strategy':'mitigar', 'description':'Implantar respaldos', 'owner':'Tecnología', 'start_date':'2020-01-01', 'target_date':'2020-02-01', 'priority':'alta', 'status':'pendiente'}
            created_treatment = await client.post('/api/v1/risk-treatments', json=treatment, headers=headers)
            assert created_treatment.status_code == 201 and created_treatment.json()['overdue'] is True
            treatment_id = created_treatment.json()['id']
            assert (await client.post(f'/api/v1/risks/{risk_id}/controls', json={'control_id':control_id}, headers=headers)).status_code == 201
            assert (await client.post(f'/api/v1/risks/{risk_id}/controls', json={'control_id':control_id}, headers=headers)).status_code == 409
            assert (await client.post(f'/api/v1/risk-treatments/{treatment_id}/controls', json={'control_id':control_id}, headers=headers)).status_code == 201
            assert len((await client.get(f'/api/v1/risk-treatments/{treatment_id}/controls', headers=headers)).json()) == 1
            assert (await client.post('/api/v1/risk-treatments', json=treatment | {'strategy':'aceptar'}, headers=headers)).status_code == 422
            accepted = treatment | {'strategy':'aceptar', 'acceptance_authority':'Dirección', 'acceptance_justification':'Riesgo asumido', 'acceptance_date':'2020-01-01', 'acceptance_review_date':'2021-01-01'}
            assert (await client.post('/api/v1/risk-treatments', json=accepted, headers=headers)).status_code == 201
            assert (await client.put(f'/api/v1/risk-treatments/{treatment_id}', json=treatment | {'status':'cerrado'}, headers=headers)).json()['overdue'] is False
            assert len((await client.get(f'/api/v1/risks/{risk_id}/assessments', headers=headers)).json()) == 2
            assert (await client.post('/api/v1/assets', json={'code':'A-2', 'name':'=1+1', 'description':'Coma, salto\nde línea'}, headers=headers)).status_code == 201
            report = await client.get('/api/v1/reports/assets.csv', params={'separator':'punto_coma', 'q':'=1+1'}, headers=headers)
            assert report.status_code == 200 and report.content.startswith(b'\xef\xbb\xbf')
            rows = list(csv.reader(io.StringIO(report.content.decode('utf-8-sig')), delimiter=';'))
            assert len(rows) == 2 and rows[1][2] == "'=1+1" and rows[1][3] == 'Coma, salto\nde línea'
            risk_report = await client.get('/api/v1/reports/risks.csv', params={'asset_id':asset_id}, headers=headers)
            assert risk_report.status_code == 200 and 'crítico' in risk_report.content.decode('utf-8-sig')
            token = (await client.post('/api/v1/auth/login', json={'username':'audit','password':'test-password'})).json()['access_token']
            assert (await client.post('/api/v1/assets', json=asset, headers={'Authorization':'Bearer '+token})).status_code == 403
            assert (await client.post('/api/v1/controls', json={'code':'NO', 'name':'Denegado'}, headers={'Authorization':'Bearer '+token})).status_code == 403
            audit = await client.get('/api/v1/audit-logs', headers={'Authorization':'Bearer '+token})
            assert audit.status_code == 200
            assert any(row['action'] == 'exportar' and row['entity'] == 'activos' for row in audit.json())
            assert any(row['action'] == 'vincular_control' for row in audit.json())
            assert (await client.get('/api/v1/users', headers={'Authorization':'Bearer '+token})).status_code == 403
            created_user = await client.post('/api/v1/users', json={'username':'gestor1', 'password':'clave-larga-de-prueba', 'role':'gestor'}, headers=headers)
            assert created_user.status_code == 201 and 'password_hash' not in created_user.json()
            manager_token = (await client.post('/api/v1/auth/login', json={'username':'gestor1', 'password':'clave-larga-de-prueba'})).json()['access_token']
            manager_headers = {'Authorization':'Bearer '+manager_token}
            assert (await client.post('/api/v1/auth/change-password', json={'current_password':'incorrecta', 'new_password':'otra-clave-larga'}, headers=manager_headers)).status_code == 400
            assert (await client.post('/api/v1/auth/change-password', json={'current_password':'clave-larga-de-prueba', 'new_password':'otra-clave-larga'}, headers=manager_headers)).status_code == 204
            assert (await client.get('/api/v1/auth/me', headers=manager_headers)).status_code == 401
            manager_token = (await client.post('/api/v1/auth/login', json={'username':'gestor1', 'password':'otra-clave-larga'})).json()['access_token']
            manager_headers = {'Authorization':'Bearer '+manager_token}
            assert (await client.post('/api/v1/auth/logout', headers=manager_headers)).status_code == 204
            assert (await client.get('/api/v1/auth/me', headers=manager_headers)).status_code == 401
            admin_id = (await client.get('/api/v1/auth/me', headers=headers)).json()['id']
            assert (await client.put(f'/api/v1/users/{admin_id}', json={'role':'auditor','active':False}, headers=headers)).status_code == 409
            manager_token = (await client.post('/api/v1/auth/login', json={'username':'gestor1', 'password':'otra-clave-larga'})).json()['access_token']
            assert (await client.put(f"/api/v1/users/{created_user.json()['id']}", json={'role':'gestor','active':False}, headers=headers)).status_code == 200
            assert (await client.get('/api/v1/auth/me', headers={'Authorization':'Bearer '+manager_token})).status_code == 401
            assert (await client.post(f'/api/v1/assets/{asset_id}/retire', headers=headers)).json()['status'] == 'retirado'
            assert (await client.post(f'/api/v1/assets/{asset_id}/assessments', json=values | {'availability':3}, headers=headers)).status_code == 409
    try:
        asyncio.run(exercise())
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_risk_level_boundaries():
    from app.main import risk_level
    assert [risk_level(x) for x in (1, 4, 5, 9, 10, 16, 17, 25)] == ['bajo', 'bajo', 'medio', 'medio', 'alto', 'alto', 'crítico', 'crítico']
