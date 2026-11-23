import os
from datetime import datetime, timedelta, timezone
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .db import get_db
from .models import Asset, AuditLog, User

# No fallback secret: startup must fail when configuration is incomplete.
SECRET = os.environ.get("SAKURA_SECRET_KEY", "")
if len(SECRET) < 32:
    raise RuntimeError("SAKURA_SECRET_KEY debe contener al menos 32 caracteres")
app = FastAPI(title="Sakura Risk Manager", docs_url=None, redoc_url=None, openapi_url=None)
bearer = HTTPBearer()
hasher = PasswordHasher()

class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)

class AssetCreate(BaseModel):
    code: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)

class AssetRead(AssetCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    status: str
    created_at: datetime

def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET, algorithms=["HS256"], options={"require": ["exp", "sub"]})
        user = db.get(User, int(payload["sub"]))
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(401, "Sesión inválida")
    if not user or not user.active:
        raise HTTPException(401, "Sesión inválida")
    return user

@app.get("/api/v1/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/auth/login")
def login(data: Login, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == data.username))
    try:
        valid = bool(user and hasher.verify(user.password_hash, data.password))
    except (VerifyMismatchError, InvalidHashError):
        valid = False
    if not valid or not user.active:
        raise HTTPException(401, "Credenciales inválidas")
    user.last_login = datetime.now(timezone.utc)
    db.add(AuditLog(user_id=user.id, action="inicio_sesion", entity="usuario", entity_id=str(user.id)))
    db.commit()
    token = jwt.encode({"sub": str(user.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=15)}, SECRET, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "expires_in": 900}

@app.get("/api/v1/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}

@app.get("/api/v1/assets", response_model=list[AssetRead])
def list_assets(offset: int = 0, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role not in {"administrador", "gestor", "auditor"}:
        raise HTTPException(403, "Acceso denegado")
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Paginación inválida")
    return db.scalars(select(Asset).order_by(Asset.id).offset(offset).limit(limit)).all()

@app.post("/api/v1/assets", response_model=AssetRead, status_code=201)
def create_asset(data: AssetCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role not in {"administrador", "gestor"}:
        raise HTTPException(403, "Acceso denegado")
    asset = Asset(**data.model_dump())
    db.add(asset)
    try:
        db.flush()
        db.add(AuditLog(user_id=user.id, action="crear", entity="activo", entity_id=str(asset.id)))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El código ya existe")
    return asset
