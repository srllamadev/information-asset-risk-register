FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --gid 10001 sakura && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sakura && mkdir /data && chown 10001:10001 /data
COPY pyproject.toml alembic.ini ./
COPY app ./app
COPY alembic ./alembic
RUN pip install --no-cache-dir .
COPY entrypoint.sh /app/entrypoint.sh
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
