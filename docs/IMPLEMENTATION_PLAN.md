# Plan de implementación

## Arquitectura y contratos

Aplicación monolítica modular: React/Vite consume `/api/v1` a través de Nginx; FastAPI aplica autenticación y autorización; SQLAlchemy usa SQLite local con claves foráneas, WAL y timeout. Alembic controla el esquema. Una sola instancia de backend limita la contención de escritura. Los timestamps se almacenan en UTC. No se utilizan servicios externos.

El esquema objetivo incluye usuarios y roles, unidades y procesos, activos y dependencias, valoraciones CIA históricas, catálogos de amenazas y vulnerabilidades, escenarios, versiones de metodología y evaluaciones inmutables, controles, tratamientos, referencias normativas, configuración y auditoría. Las relaciones tendrán claves foráneas y restricciones; las evaluaciones guardarán una instantánea de la metodología. Los controles y tratamientos se relacionan mediante tablas de asociación.

Los contratos iniciales son JSON bajo `/api/v1`: `POST /auth/login` recibe usuario y contraseña y entrega token temporal; `GET /auth/me` devuelve la identidad verificada; `GET/POST /assets` consulta y crea activos; `GET /health` permite comprobar disponibilidad. Todas las operaciones salvo salud e inicio de sesión requieren identidad; el backend decide permisos. Errores usan `detail` y códigos HTTP estándar. Las listas estarán paginadas. Los contratos se ampliarán junto a cada módulo.

La metodología inicial usa máximo CIA y probabilidad × impacto (1–25), con niveles 1–4, 5–9, 10–16 y 17–25. Es una propuesta institucional, no un requisito ni fórmula impuesta por ISO o NIST. La evaluación residual requiere estimaciones y justificación propias; una reevaluación crea una versión nueva.

## Fases y tareas comprobables

- [x] Inspeccionar repositorio y definir arquitectura y contratos iniciales.
- [ ] Backend: migraciones, inicialización segura, autenticación, permisos y auditoría completos.
- [ ] Inventario, unidades y valoraciones CIA con historial y pruebas.
- [ ] Catálogos, riesgos, metodología versionada, controles y tratamientos con pruebas.
- [ ] Dashboard, matriz, reportes CSV seguros y trazabilidad normativa.
- [ ] Interfaz React accesible conectada a todos los flujos.
- [ ] Contenedores, proxy, persistencia, respaldo y restauración.
- [ ] Ejecutar migraciones, pruebas, lint, build, Compose y comprobar persistencia.
- [ ] Documentar operación, HTTPS, seguridad y despliegue sin conexión.

## Estado y límites de esta entrega

Se dispone de unidades organizacionales, inventario básico con retiro lógico y filtros, valoraciones CIA históricas, alta y consulta de amenazas y vulnerabilidades, escenarios y evaluaciones de riesgo históricas con metodología inicial fija. La metodología todavía no es configurable ni existe un flujo de aprobación. Las valoraciones y evaluaciones solo se agregan mediante la API; aún no hay controles de inmutabilidad frente a escritura directa en la base. No se considera un MVP terminado ni apto para producción: faltan, entre otros, protección ante intentos de acceso, cierre de sesión revocable, administración de usuarios, asignación y alcance por responsable, tratamientos, controles, reportes, frontend, contenedores y auditoría completa. No desplegar hasta completar y revisar esas funciones. SQLite necesita almacenamiento local persistente; no usar un volumen de red sin validar y no escalar escritores sin controlar concurrencia.

## Verificación de esta fase

- Migraciones 0001–0003 aplicadas a una base temporal; `alembic check` no detectó diferencias.
- Dos pruebas de backend pasaron fuera del aislamiento; el portal de hilos de las pruebas se bloquea dentro de este entorno.
- Sigue pendiente probar las migraciones inversas, concurrencia, frontend, Docker, persistencia entre reinicios y los flujos aún no implementados.
