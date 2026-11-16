"""Upgrading an older database keeps every row and adds what the newer schema needs."""

import pytest
from sqlalchemy import inspect, select, text
from test_collection_store import POSTGRES, postgres_database

from nyctr.database import _V2_COLUMNS, _V2_TABLES, make_engine, migrate, session_factory
from nyctr.models import AccessRequest, Base, SchemaVersion, User
from nyctr.seed import seed_demo


def test_schema_one_database_is_upgraded_in_place(tmp_path):
    """A database created by the first release gains the new tables and columns without losing data."""
    engine = make_engine(f"sqlite:///{tmp_path}/old.db")
    with engine.begin() as connection:
        old = [t for name, t in Base.metadata.tables.items() if name not in (*_V2_TABLES, "device_presence")]
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
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == [1, 2, 3]
        row = db.get(AccessRequest, "r1")
        assert row.domain == "example.com" and row.risk_score is None and row.decided_by is None
        assert db.get(User, "u1").name == "A"


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_an_alpha_6_database_gains_only_the_table_of_ties_and_keeps_every_row(tmp_path, request, engine_kind):
    """Schema 2, filled with the demonstration's rows, upgrades to 3 with every stored row unchanged."""
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/a6.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    ties = Base.metadata.tables["device_presence"]
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": 1}, {"version": 2}])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()
    with engine.begin() as connection:
        ties.drop(connection)  # alpha.6 had every table but this one

    def everything():
        with engine.connect() as connection:
            return {name: sorted(map(repr, connection.execute(text(f"SELECT * FROM {name}"))))
                    for name in inspect(connection).get_table_names() if name != "schema_versions"}

    before = everything()
    assert "device_presence" not in before and sum(map(len, before.values())) > 100
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    after = everything()
    assert after.pop("device_presence") == [] and after == before
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == [1, 2, 3]
    engine.dispose()
