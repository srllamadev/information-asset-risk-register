"""SQLite online backup and offline restore. The restore requires exclusive access."""
import argparse
from contextlib import closing
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from sqlalchemy.engine import make_url


def database_path():
    url = make_url(os.environ.get("DATABASE_URL", "sqlite:///./sakura.db"))
    if url.drivername != "sqlite" or not url.database or url.database == ":memory:":
        raise ValueError("Se requiere una base SQLite en disco")
    return Path(url.database).resolve()


def check_database(path: Path):
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("El respaldo no supera integrity_check")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"alembic_version", "users", "assets", "risk_scenarios"}.issubset(tables):
            raise ValueError("El archivo no contiene el esquema esperado de Sakura")
        if db.execute("SELECT count(*) FROM alembic_version").fetchone()[0] != 1:
            raise ValueError("El respaldo no tiene una versión de migración válida")


def backup(source: Path, output):
    if not source.is_file():
        raise ValueError("La base de datos no existe")
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "backup.db"
        with closing(sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)) as src, closing(sqlite3.connect(snapshot)) as dst:
            src.backup(dst)
        check_database(snapshot)
        with snapshot.open("rb") as stream:
            shutil.copyfileobj(stream, output)


def restore(target: Path, source):
    # The caller must stop every process accessing target before invoking restore.
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tempname = tempfile.mkstemp(prefix=".sakura-restore-", suffix=".db", dir=target.parent)
    candidate = Path(tempname)
    try:
        with os.fdopen(fd, "wb") as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        check_database(candidate)
        if target.exists():
            with closing(sqlite3.connect(target, timeout=10)) as db:
                result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if result and result[0] != 0:
                    raise ValueError("No se pudo cerrar el WAL; detenga todos los procesos")
        for suffix in ("-wal", "-shm"):
            Path(str(target) + suffix).unlink(missing_ok=True)
        os.replace(candidate, target)
        directory = os.open(target.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        candidate.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("backup", "restore", "verify"))
    args = parser.parse_args()
    try:
        if args.operation == "backup":
            backup(database_path(), sys.stdout.buffer)
        elif args.operation == "restore":
            restore(database_path(), sys.stdin.buffer)
        else:
            check_database(database_path())
            print("Integridad y esquema verificados")
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
