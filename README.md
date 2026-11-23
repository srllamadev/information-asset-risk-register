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

## Interfaz en desarrollo

Desde `frontend/`, instale las dependencias con `npm ci` y ejecute `npm run dev`. Abra `http://127.0.0.1:5173`; Vite dirige `/api` al backend en `127.0.0.1:8000`. Inicie primero el backend y cree el administrador con el procedimiento anterior. La interfaz incluye matriz de riesgos, controles, tratamientos, usuarios, perfil, auditoría y los reportes CSV iniciales además de los módulos iniciales, pero solo cubre una parte del sistema; revise el plan para los módulos pendientes. La sesión del navegador se mantiene en memoria y debe iniciarse nuevamente al recargar.

## Pruebas

Desde `backend/`, con el entorno virtual activado, ejecute `pytest -q`. Las pruebas usan una base independiente en memoria. En el entorno de desarrollo utilizado, el aislamiento bloqueó el mecanismo de hilos de las pruebas; la ejecución fuera del aislamiento pasó.

Los controles se vinculan con riesgos o tratamientos. El vencimiento de un tratamiento se calcula según su fecha objetivo y estado; cerrar un plan no cambia la evaluación residual. La aceptación registrada todavía no cuenta con flujo independiente de aprobación ni historial inmutable. Las exportaciones CSV admiten `separator=coma` o `separator=punto_coma` y se registran en auditoría.

La protección inicial permite cinco intentos por nombre en una ventana de 15 minutos. Una cuenta puede quedar bloqueada temporalmente por intentos de terceros; hacen falta controles adicionales contra ataques distribuidos. Los roles responsable y consulta no tienen todavía alcance de datos configurado. La documentación interactiva puede habilitarse solo para desarrollo local mediante `SAKURA_ENABLE_DOCS=1`; permanece deshabilitada por defecto.

En `frontend/`, `npm test` ejecuta las pruebas disponibles y `npm run build` genera la compilación. Las pruebas actuales no cubren todavía la navegación ni los flujos de usuario en navegador.

## Docker Compose y operación local

Los archivos de despliegue están preparados, pero **no se han construido ni probado con Docker en este entorno**. La aplicación sigue incompleta y debe mantenerse en un entorno de pruebas hasta completar la revisión de seguridad y las pruebas de aceptación. Requiere Docker Engine con el complemento Compose v2.

En el directorio raíz, cree el archivo local de configuración con permisos restringidos y una clave aleatoria. El siguiente comando no imprime la clave; no sustituya un `.env` existente sin conservar su clave:

```sh
umask 077
python3 -c 'import pathlib,secrets; p=pathlib.Path(".env"); p.write_text("SAKURA_SECRET_KEY="+secrets.token_urlsafe(48)+"\nBIND_ADDRESS=127.0.0.1\nHTTP_PORT=8080\n") if not p.exists() else print(".env ya existe; se conserva")'
docker compose config --quiet
docker compose up -d --build
docker compose ps
```

Cree el primer administrador de forma interactiva y sin transmitir la contraseña como argumento:

```sh
docker compose exec backend python -m app.bootstrap
```

La interfaz se sirve en `http://127.0.0.1:8080`. Solamente Nginx publica un puerto; FastAPI está en la red interna de Compose. El volumen `sakura_data` conserva `/data/sakura.db` entre reinicios y recreaciones de contenedores. El backend aplica migraciones al arrancar; no ejecute varias instancias de backend ni restaure mientras haya otro proceso usando la base. Los contenedores usan usuarios sin privilegios, raíz de sistema de archivos de solo lectura, almacenamiento temporal y límites definidos en Compose.

### Red y HTTPS

Por defecto se escucha solo en la propia máquina. `BIND_ADDRESS` admite una dirección IPv4 local y `HTTP_PORT` ajusta el puerto publicado. Para acceso institucional configure HTTPS con un certificado válido para el DNS interno y un proxy TLS aprobado delante de Nginx; mantenga el puerto HTTP de Compose en localhost y publique únicamente el extremo HTTPS del proxy. Configure firewall y acceso según las políticas de la entidad. El archivo Compose no proporciona TLS. No exponga HTTP en la red institucional ni considere Docker una garantía de aislamiento o seguridad.

### Respaldo y restauración

Los siguientes comandos se ejecutan desde la raíz. El respaldo usa `sqlite3.Connection.backup` y comprueba integridad y esquema antes de generar el archivo. La carpeta de destino debe existir, ser privada y encontrarse fuera del volumen activo:

```sh
./deployment/scripts/backup.sh ./respaldo-2026-01-01.db
```

Para comprobar el archivo con Python estándar, sin alterar la base activa:

```sh
python3 -c 'import sqlite3,sys; c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); print(c.execute("PRAGMA integrity_check").fetchone()[0]); print(c.execute("SELECT version_num FROM alembic_version").fetchone()[0])' ./respaldo-2026-01-01.db
```

Ensaye regularmente la restauración en una instalación aislada y compruebe registros, permisos y acceso. Para restaurar una copia en esta instalación, detenga cualquier otro proceso o réplica que acceda al volumen y haga primero un respaldo actual. La operación siguiente sustituye la base activa, detiene el backend y lo reinicia solo si la restauración se valida correctamente:

```sh
./deployment/scripts/restore.sh ./respaldo-2026-01-01.db --confirmar
```

Si falla, el backend queda detenido para investigación. No use copias en caliente del archivo `.db` ni almacene SQLite en un recurso de red sin validar. Elimine o archive los respaldos según la política institucional y protéjalos como información sensible. No ejecute `docker compose down -v` salvo que pretenda borrar el volumen y haya verificado una copia restaurable.

### Traslado sin conexión

En una máquina conectada, construya las imágenes para la arquitectura del servidor y expórtelas junto con una copia de este proyecto, excluyendo `.env` y bases de datos:

```sh
docker compose build
docker save -o sakura-imagenes.tar sakura-risk-manager-backend:0.1.0 sakura-risk-manager-frontend:0.1.0
```

Transfiera los artefactos por un medio autorizado. En el servidor sin Internet, instale previamente Docker y Compose, cargue las imágenes con `docker load -i sakura-imagenes.tar`, configure un `.env` nuevo y ejecute `docker compose up -d --no-build`. Verifique integridad de los artefactos antes de transferirlos y compruebe que la arquitectura de las imágenes coincida con la del servidor. Para actualizar, cree un respaldo verificable, ensaye la actualización en un entorno aislado y conserve tanto las imágenes anteriores como el respaldo; las migraciones ocurren al iniciar.

El inventario permite registrar los datos institucionales ampliados, editar y retirar activos, y asociar dependencias dirigidas. Las categorías sugeridas aún no son un catálogo administrable, y los responsables y procesos son texto libre: estos campos todavía no conceden permisos.
