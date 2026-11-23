import asyncio
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
            token = (await client.post('/api/v1/auth/login', json={'username':'audit','password':'test-password'})).json()['access_token']
            assert (await client.post('/api/v1/assets', json=asset, headers={'Authorization':'Bearer '+token})).status_code == 403
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
