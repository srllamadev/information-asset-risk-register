import os
os.environ['SAKURA_SECRET_KEY'] = 'test-only-secret-key-with-32-characters'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
from app.main import app
from app.models import User


def test_login_authorization_and_unique_assets():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions() as db:
        db.add_all([User(username='admin', password_hash=PasswordHasher().hash('test-password'), role='administrador'), User(username='audit', password_hash=PasswordHasher().hash('test-password'), role='auditor')])
        db.commit()
    def override():
        with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = override
    try:
        with TestClient(app) as client:
            assert client.get('/api/v1/assets').status_code == 403
            assert client.post('/api/v1/auth/login', json={'username':'admin','password':'wrong'}).status_code == 401
            token = client.post('/api/v1/auth/login', json={'username':'admin','password':'test-password'}).json()['access_token']
            headers = {'Authorization': 'Bearer ' + token}
            asset = {'code':'A-1','name':'Servidor'}
            assert client.post('/api/v1/assets', json=asset, headers=headers).status_code == 201
            assert client.post('/api/v1/assets', json=asset, headers=headers).status_code == 409
            assert len(client.get('/api/v1/assets', headers=headers).json()) == 1
            token = client.post('/api/v1/auth/login', json={'username':'audit','password':'test-password'}).json()['access_token']
            assert client.post('/api/v1/assets', json=asset, headers={'Authorization':'Bearer '+token}).status_code == 403
    finally:
        app.dependency_overrides.clear()
