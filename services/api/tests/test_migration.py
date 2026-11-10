"""Upgrading a schema-1 database keeps its rows and adds schema 2."""

from sqlalchemy import inspect, select, text

from nyctr.database import _V2_COLUMNS, _V2_TABLES, make_engine, migrate, session_factory
from nyctr.models import AccessRequest, Base, SchemaVersion, User


def test_schema_one_database_is_upgraded_in_place(tmp_path):
    """A database created by the first release gains the new tables and columns without losing data."""
    engine = make_engine(f"sqlite:///{tmp_path}/old.db")
    with engine.begin() as connection:
        old = [t for name, t in Base.metadata.tables.items() if name not in _V2_TABLES]
        Base.metadata.create_all(connection, tables=old)
        for table, names in _V2_COLUMNS.items():
            for name in names:
                connection.execute(text(f"ALTER TABLE {table} DROP COLUMN {name}"))
        connection.execute(SchemaVersion.__table__.insert().values(version=1))
        connection.execute(text("INSERT INTO users (id, email, name, role, active) "
                                "VALUES ('u1', 'a@example.net', 'A', 'member', 1)"))
        connection.execute(text(
            "INSERT INTO access_requests (id, block_id, domain, device_name, requester_id, reason, "
            "duration_minutes, status, created_at) VALUES ('r1', 'b1', 'example.com', 'Laptop', 'u1', "
            "'because', 60, 'pending', '2026-11-01 10:00:00')"))
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    tables = set(inspect(engine).get_table_names())
    assert set(_V2_TABLES) <= tables
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == [1, 2]
        row = db.get(AccessRequest, "r1")
        assert row.domain == "example.com" and row.risk_score is None and row.decided_by is None
        assert db.get(User, "u1").name == "A"
