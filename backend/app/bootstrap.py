"""Create the first administrator interactively after applying migrations."""
import getpass
from argon2 import PasswordHasher
from sqlalchemy import select
from .db import SessionLocal
from .models import User, AuditLog

def main():
    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.role == "administrador")) is not None:
            raise SystemExit("Ya existe un administrador; inicialización cancelada.")
        username = input("Usuario administrador: ").strip()
        password = getpass.getpass("Contraseña (mínimo 12 caracteres): ")
        confirmation = getpass.getpass("Repita la contraseña: ")
        if not username or len(username) > 100 or len(password) < 12 or password != confirmation:
            raise SystemExit("Datos inválidos; no se creó el usuario.")
        user = User(username=username, password_hash=PasswordHasher().hash(password), role="administrador")
        db.add(user)
        db.flush()
        db.add(AuditLog(user_id=user.id, action="inicializar", entity="usuario", entity_id=str(user.id)))
        db.commit()
        print("Administrador creado.")

if __name__ == "__main__":
    main()
