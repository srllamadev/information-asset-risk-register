# Sakura Risk Manager

Base inicial de un sistema institucional de activos y riesgos. **Esta entrega está incompleta y no está lista para producción ni pruebas de aceptación.** Consulte [el plan y sus tareas pendientes](docs/IMPLEMENTATION_PLAN.md). La metodología propuesta no garantiza certificación ni cumplimiento normativo.

## Arranque de desarrollo

Requiere Python 3.12. Desde `backend/`:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
alembic upgrade head
python -m app.bootstrap
export SAKURA_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

El administrador se crea de forma interactiva después de migrar. Conserve la clave generada en un gestor de secretos para futuras ejecuciones; cambiarla invalida los tokens. `DATABASE_URL` permite configurar la ruta SQLite local. La API inicial ofrece salud, inicio de sesión, identidad y listado/creación limitada de activos. Los tokens vencen en 15 minutos. Todavía faltan medidas esenciales, incluida la limitación de intentos y revocación de sesiones; no exponer la aplicación a una red institucional.

SQLite emplea WAL y claves foráneas; debe alojarse en almacenamiento local persistente. La concurrencia de escrituras es limitada. Los procedimientos de Docker, HTTPS, respaldos y restauración aún están pendientes.
