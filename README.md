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

El administrador se crea de forma interactiva después de migrar. Conserve la clave generada en un gestor de secretos para futuras ejecuciones; cambiarla invalida los tokens. `DATABASE_URL` permite configurar la ruta SQLite local. La API inicial ofrece salud, inicio de sesión, identidad, unidades, inventario básico, valoraciones CIA, catálogos de amenazas y vulnerabilidades, escenarios y evaluaciones de riesgo, controles, tratamientos, consulta de auditoría y exportaciones iniciales CSV de activos y riesgos. Las evaluaciones se agregan como nuevas entradas; la metodología inicial está fijada en código y todavía no es configurable. Los tokens vencen en 15 minutos. Se limitan los intentos por nombre de usuario y se revocan sesiones al cerrar sesión o cambiar credenciales. Faltan medidas esenciales y revisión de seguridad; no exponer la aplicación a una red institucional.

SQLite emplea WAL y claves foráneas; debe alojarse en almacenamiento local persistente. La concurrencia de escrituras es limitada. Los procedimientos de Docker, HTTPS, respaldos y restauración aún están pendientes.

## Pruebas

Desde `backend/`, con el entorno virtual activado, ejecute `pytest -q`. Las pruebas usan una base independiente en memoria. En el entorno de desarrollo utilizado, el aislamiento bloqueó el mecanismo de hilos de las pruebas; la ejecución fuera del aislamiento pasó.

Los controles se vinculan con riesgos o tratamientos. El vencimiento de un tratamiento se calcula según su fecha objetivo y estado; cerrar un plan no cambia la evaluación residual. La aceptación registrada todavía no cuenta con flujo independiente de aprobación ni historial inmutable. Las exportaciones CSV admiten `separator=coma` o `separator=punto_coma` y se registran en auditoría.

La protección inicial permite cinco intentos por nombre en una ventana de 15 minutos. Una cuenta puede quedar bloqueada temporalmente por intentos de terceros; hacen falta controles adicionales contra ataques distribuidos. Los roles responsable y consulta no tienen todavía alcance de datos configurado. La documentación interactiva puede habilitarse solo para desarrollo local mediante `SAKURA_ENABLE_DOCS=1`; permanece deshabilitada por defecto.
