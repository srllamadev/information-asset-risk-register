import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def test_upgrade_preserves_existing_assets(tmp_path):
    project = Path(__file__).resolve().parents[1]
    database = tmp_path / 'migration.db'
    env = dict(os.environ, DATABASE_URL=f'sqlite:///{database}')
    def migrate(revision):
        subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', revision], cwd=project, env=env, check=True, capture_output=True)
    migrate('0006')
    with sqlite3.connect(database) as db:
        db.execute("INSERT INTO assets (code, name, description, status, created_at) VALUES ('LEG-1', 'Existente', 'Datos previos', 'activo', '2025-01-01 00:00:00')")
    migrate('head')
    with sqlite3.connect(database) as db:
        row=db.execute('SELECT code, name, description, updated_at, category FROM assets').fetchone()
        assert row[:3] == ('LEG-1', 'Existente', 'Datos previos')
        assert row[3].startswith('2025-01-01') and row[4] is None
        assert db.execute('SELECT version_num FROM alembic_version').fetchone() == ('0007',)
