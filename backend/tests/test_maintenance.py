import io
import sqlite3
from contextlib import closing
import pytest
from app.maintenance import backup, check_database, restore


def create_database(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE alembic_version (version_num TEXT)')
    db.execute("INSERT INTO alembic_version VALUES ('0006')")
    db.execute('CREATE TABLE users (name TEXT)')
    db.execute('CREATE TABLE assets (name TEXT)')
    db.execute('CREATE TABLE risk_scenarios (name TEXT)')
    db.execute("INSERT INTO assets VALUES ('dato respaldado')")
    db.commit()
    return db


def test_backup_captures_wal_and_restore(tmp_path):
    path = tmp_path / 'source.db'
    connection = create_database(path)
    result = io.BytesIO()
    backup(path, result)
    connection.execute("INSERT INTO assets VALUES ('dato posterior')")
    connection.commit()
    connection.close()
    target = tmp_path / 'target.db'
    old = create_database(target)
    old.execute("INSERT INTO assets VALUES ('dato reemplazado')")
    old.commit()
    old.close()
    restore(target, io.BytesIO(result.getvalue()))
    check_database(target)
    with closing(sqlite3.connect(target)) as db:
        assert db.execute('SELECT name FROM assets').fetchall() == [('dato respaldado',)]


def test_invalid_restore_leaves_existing_database_intact(tmp_path):
    target = tmp_path / 'target.db'
    create_database(target).close()
    with pytest.raises((sqlite3.Error, ValueError)):
        restore(target, io.BytesIO(b'not a database'))
    with closing(sqlite3.connect(target)) as db:
        assert db.execute('SELECT name FROM assets').fetchall() == [('dato respaldado',)]
