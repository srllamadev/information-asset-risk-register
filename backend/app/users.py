"""User administration and revocable sessions."""
from datetime import datetime
from typing import Literal
import jwt
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .db import get_db
from .main import SECRET, UTCResponse, bearer, current_user, hasher, require_role
from .models import AuditLog, AuthSession, User

router = APIRouter(prefix="/api/v1")
Role = Literal["administrador", "gestor", "responsable", "auditor", "consulta"]

class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=100, pattern=r"^\S+$")
    password: str = Field(min_length=12, max_length=1024)
    role: Role

class UserUpdate(BaseModel):
    role: Role
    active: bool

class UserRead(UTCResponse):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    active: bool
    last_login: datetime | None

class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)

@router.get("/users", response_model=list[UserRead])
def list_users(offset: int = 0, limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador"})
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Paginación inválida")
    return db.scalars(select(User).order_by(User.id).offset(offset).limit(limit)).all()

@router.post("/users", response_model=UserRead, status_code=201)
def create_user(data: UserCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador"})
    item = User(username=data.username, password_hash=hasher.hash(data.password), role=data.role)
    db.add(item)
    try:
        db.flush()
        db.add(AuditLog(user_id=user.id, action="crear", entity="usuario", entity_id=str(item.id)))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El usuario ya existe")
    return item

@router.put("/users/{user_id}", response_model=UserRead)
def update_user(user_id: int, data: UserUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_role(user, {"administrador"})
    # Serialize admin changes in SQLite and recheck the caller under the lock.
    db.execute(text("BEGIN IMMEDIATE"))
    db.refresh(user)
    if not user.active or user.role != "administrador":
        raise HTTPException(403, "Acceso denegado")
    item = db.get(User, user_id)
    if not item:
        raise HTTPException(404, "Usuario no encontrado")
    if item.id == user.id and (not data.active or data.role != "administrador"):
        raise HTTPException(409, "No puede desactivar ni degradar su propia cuenta")
    if item.role == "administrador" and item.active and (not data.active or data.role != "administrador"):
        count = db.scalar(select(func.count()).select_from(User).where(User.role == "administrador", User.active.is_(True)))
        if count <= 1:
            raise HTTPException(409, "Debe permanecer al menos un administrador activo")
    if item.role != data.role or item.active != data.active:
        item.role, item.active = data.role, data.active
        db.execute(update(AuthSession).where(AuthSession.user_id == item.id).values(revoked=True))
        db.add(AuditLog(user_id=user.id, action="modificar", entity="usuario", entity_id=str(item.id)))
        db.commit()
    return item

@router.post("/auth/logout", status_code=204)
def logout(credentials: HTTPAuthorizationCredentials = Depends(bearer), user: User = Depends(current_user), db: Session = Depends(get_db)):
    payload = jwt.decode(credentials.credentials, SECRET, algorithms=["HS256"], options={"require": ["exp", "sub", "jti"]})
    session = db.get(AuthSession, payload["jti"])
    session.revoked = True
    db.add(AuditLog(user_id=user.id, action="cierre_sesion", entity="usuario", entity_id=str(user.id)))
    db.commit()

@router.post("/auth/change-password", status_code=204)
def change_password(data: PasswordChange, user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        valid = hasher.verify(user.password_hash, data.current_password)
    except (VerifyMismatchError, InvalidHashError):
        valid = False
    if not valid:
        raise HTTPException(400, "Contraseña actual incorrecta")
    user.password_hash = hasher.hash(data.new_password)
    db.execute(update(AuthSession).where(AuthSession.user_id == user.id).values(revoked=True))
    db.add(AuditLog(user_id=user.id, action="cambiar_contraseña", entity="usuario", entity_id=str(user.id)))
    db.commit()
