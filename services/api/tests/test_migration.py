"""Upgrading an older database keeps every row and adds what the newer schema needs."""

import pytest
from sqlalchemy import event, inspect, select, text
from sqlalchemy.exc import IntegrityError
from test_collection_store import POSTGRES, postgres_database

from nyctr.database import (
    _V2_COLUMNS,
    _V2_TABLES,
    _V4_TABLES,
    _V6_TABLES,
    _V7_TABLES,
    _V9_TABLES,
    make_engine,
    migrate,
    session_factory,
)
from nyctr.models import AccessRequest, Base, SchemaVersion, User
from nyctr.seed import seed_demo


def _rows(engine):
    """Every stored row except the schema version list, so a test can compare a migration."""
    with engine.connect() as connection:
        return {name: sorted(map(repr, connection.execute(text(f"SELECT * FROM {name}"))))
                for name in inspect(connection).get_table_names() if name != "schema_versions"}


def test_schema_one_database_is_upgraded_in_place(tmp_path):
    """A database created by the first release gains the new tables and columns without losing data."""
    engine = make_engine(f"sqlite:///{tmp_path}/old.db")
    with engine.begin() as connection:
        old = [t for name, t in Base.metadata.tables.items()
               if name not in (*_V2_TABLES, "device_presence", *_V4_TABLES, *_V6_TABLES, *_V7_TABLES, *_V9_TABLES)]
        Base.metadata.create_all(connection, tables=old)
        for table, names in _V2_COLUMNS.items():
            for name in names:
                connection.execute(text(f"ALTER TABLE {table} DROP COLUMN {name}"))
        connection.execute(text("ALTER TABLE integrations DROP COLUMN sync_holder"))
        connection.execute(text("ALTER TABLE integrations DROP COLUMN sync_heartbeat"))
        connection.execute(text("DROP INDEX IF EXISTS uq_access_request_event"))
        connection.execute(text("DROP INDEX IF EXISTS uq_access_request_device_block"))
        connection.execute(text("DROP INDEX IF EXISTS ix_access_requests_device_id"))
        connection.execute(text("ALTER TABLE access_requests DROP COLUMN basis"))
        connection.execute(text("ALTER TABLE access_requests DROP COLUMN device_id"))
        connection.execute(text(
            "CREATE UNIQUE INDEX uq_access_requests_requester_block "
            "ON access_requests (requester_id, block_id)"))
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
    assert set(_V2_TABLES) <= tables and set(_V4_TABLES) <= tables and set(_V6_TABLES) <= tables \
        and set(_V7_TABLES) <= tables
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
        columns = {column["name"] for column in inspect(engine).get_columns("integrations")}
        assert {"sync_holder", "sync_heartbeat"} <= columns
        row = db.get(AccessRequest, "r1")
        assert row.domain == "example.com" and row.risk_score is None and row.decided_by is None
        assert row.basis is None and row.device_id is None
        assert db.get(User, "u1").name == "A"
    assert "statement_quotas" in tables


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_an_alpha_6_database_gains_only_the_table_of_ties_and_keeps_every_row(tmp_path, request, engine_kind):
    """Schema 2, which is the alpha.6 database, upgrades with every stored row unchanged."""
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/a6.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    ties = Base.metadata.tables["device_presence"]
    verdicts = Base.metadata.tables["analyses"]
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": 1}, {"version": 2}])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()
    with engine.begin() as connection:
        ties.drop(connection)  # schema 2 had every table but the sign-in ties
        verdicts.drop(connection)

    before = _rows(engine)
    assert "device_presence" not in before and "analyses" not in before and sum(map(len, before.values())) > 100
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    after = _rows(engine)
    assert after.pop("device_presence") == [] and after.pop("analyses") == [] and after == before
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
    engine.dispose()


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_schema_three_database_gains_only_the_fact_tables_and_keeps_every_row(tmp_path, request, engine_kind):
    """Schema 3 gains the fact cache and the lookup list. Later upgrades add the verdict table.

    The alpha.6 release is schema 2. The test above is that upgrade.
    """
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/a6.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    with engine.begin() as connection:
        kept = [table for name, table in Base.metadata.tables.items() if name not in (*_V4_TABLES, *_V6_TABLES)]
        Base.metadata.create_all(connection, tables=kept)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": 1}, {"version": 2}, {"version": 3}])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()

    before = _rows(engine)
    assert set(_V4_TABLES).isdisjoint(before) and set(_V6_TABLES).isdisjoint(before)
    assert sum(map(len, before.values())) > 100
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    after = _rows(engine)
    assert after.pop("fact_cache") == [] and after.pop("own_lookups") == [] and after.pop("analyses") == []
    assert after == before
    with engine.connect() as connection:
        present = set(inspect(connection).get_table_names())
        columns = {name: [column["name"] for column in inspect(connection).get_columns(name)] for name in _V4_TABLES}
    assert set(_V4_TABLES) <= present and columns == {
        "fact_cache": ["domain", "kind", "value", "state", "fetched_at"],
        "own_lookups": ["id", "name", "at"]}
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
    engine.dispose()


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_schema_four_database_gains_only_the_lease_columns_and_keeps_every_row(tmp_path, request, engine_kind):
    """Schema 4 gains the collection holder's id and heartbeat, and every stored row stays."""
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/a6.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        connection.execute(SchemaVersion.__table__.insert(),
                           [{"version": 1}, {"version": 2}, {"version": 3}, {"version": 4}])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()
    # The rows are stored first. Dropping the columns afterwards is what a schema 4 database looks like.
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE integrations DROP COLUMN sync_holder"))
        connection.execute(text("ALTER TABLE integrations DROP COLUMN sync_heartbeat"))

    before = _rows(engine)
    assert sum(map(len, before.values())) > 100
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    after = _rows(engine)
    stored_before, stored_after = before.pop("integrations"), after.pop("integrations")
    assert after == before and len(stored_after) == len(stored_before) > 0
    with engine.connect() as connection:
        columns = {column["name"] for column in inspect(connection).get_columns("integrations")}
        holders = connection.execute(text("SELECT sync_holder, sync_heartbeat FROM integrations")).all()
    assert {"sync_holder", "sync_heartbeat"} <= columns
    assert holders and all(row == (None, None) for row in holders)
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
    engine.dispose()


_VERDICT_COLUMNS = ["id", "block_id", "domain", "facts", "rule_score", "model_name", "verdict", "risk", "reasons",
                    "uncertainty", "model_state", "trace_id", "prompt_version", "duration_ms", "created_at"]


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_schema_five_database_gains_only_the_verdict_table_and_keeps_every_row(tmp_path, request, engine_kind):
    """A schema 5 database gains the verdict table and nothing else."""
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/s5.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    with engine.begin() as connection:
        kept = [table for name, table in Base.metadata.tables.items() if name not in _V6_TABLES]
        Base.metadata.create_all(connection, tables=kept)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": number} for number in (1, 2, 3, 4, 5)])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()

    before = _rows(engine)
    assert set(_V6_TABLES).isdisjoint(before) and sum(map(len, before.values())) > 100
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    after = _rows(engine)
    assert after.pop("analyses") == [] and after == before
    with engine.connect() as connection:
        present = set(inspect(connection).get_table_names())
        columns = [column["name"] for column in inspect(connection).get_columns("analyses")]
    assert "analyses" in present and columns == _VERDICT_COLUMNS
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
    engine.dispose()


_NOTICE_COLUMNS = ["id", "kind", "subject", "payload", "state", "attempts", "next_try_at", "last_status",
                   "created_at", "claimed_by", "claimed_at"]


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_schema_six_database_gains_only_the_notice_table_and_keeps_every_row(tmp_path, request, engine_kind):
    """A schema 6 database gains the notice table and nothing else."""
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/s6.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    with engine.begin() as connection:
        kept = [table for name, table in Base.metadata.tables.items() if name not in _V7_TABLES]
        Base.metadata.create_all(connection, tables=kept)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": number} for number in (1, 2, 3, 4, 5, 6)])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()

    before = _rows(engine)
    assert set(_V7_TABLES).isdisjoint(before) and sum(map(len, before.values())) > 100
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    after = _rows(engine)
    assert after.pop("notices") == [] and after == before
    with engine.connect() as connection:
        present = set(inspect(connection).get_table_names())
        columns = [column["name"] for column in inspect(connection).get_columns("notices")]
    assert "notices" in present and columns == _NOTICE_COLUMNS
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
    engine.dispose()


def _analysis_column_adds(statements):
    """Column names from ALTER TABLE access_requests ADD COLUMN, in the order they were sent."""
    added = []
    for statement in statements:
        words = " ".join(statement.split()).split()
        if [word.upper() for word in words[:5]] == ["ALTER", "TABLE", "ACCESS_REQUESTS", "ADD", "COLUMN"]:
            added.append(words[5])
    return added


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_schema_seven_database_gains_only_the_analysis_columns_and_keeps_every_row(tmp_path, request, engine_kind):
    """Schema 7 gains the analysis and its claim on a request, and every stored row stays."""
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/s7.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": number} for number in range(1, 8)])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()
    # The rows are stored first. Dropping the columns afterwards is what a schema 7 database looks like.
    with engine.begin() as connection:
        for name in ("analysis_id", "analysis_holder", "analysis_claimed_at"):
            connection.execute(text(f"ALTER TABLE access_requests DROP COLUMN {name}"))
    with engine.connect() as connection:
        request_columns = [column["name"] for column in inspect(connection).get_columns("access_requests")]
    assert {"analysis_id", "analysis_holder", "analysis_claimed_at"}.isdisjoint(request_columns)
    assert all(name.isidentifier() for name in request_columns)

    def request_values():
        listed = ", ".join(request_columns)
        with engine.connect() as connection:
            return sorted(map(repr, connection.execute(text(f"SELECT {listed} FROM access_requests")).all()))

    before_requests = request_values()
    before = _rows(engine)
    assert sum(map(len, before.values())) > 100
    heard = []

    def capture(_connection, _cursor, statement, _parameters, _context, _executemany):
        heard.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        migrate(engine)
        added = _analysis_column_adds(heard)
        heard.clear()
        migrate(engine)  # A second start must be a no-op.
        again = _analysis_column_adds(heard)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert added == ["analysis_id", "analysis_holder", "analysis_claimed_at"] and again == []
    after = _rows(engine)
    stored_before, stored_after = before.pop("access_requests"), after.pop("access_requests")
    assert after == before and len(stored_after) == len(stored_before) > 0
    assert request_values() == before_requests
    with engine.connect() as connection:
        columns = {column["name"] for column in inspect(connection).get_columns("access_requests")}
        claims = connection.execute(
            text("SELECT analysis_id, analysis_holder, analysis_claimed_at FROM access_requests")).all()
    assert {"analysis_id", "analysis_holder", "analysis_claimed_at"} <= columns
    assert claims and all(row == (None, None, None) for row in claims)
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
    engine.dispose()


def _drop_device_indexes(connection) -> None:
    """Remove indexes that name the device, so the column can go back off as it was in schema 8."""
    if connection.dialect.name == "postgresql":
        names = connection.execute(text(
            "SELECT indexrel.relname FROM pg_index idx "
            "JOIN pg_class indexrel ON indexrel.oid = idx.indexrelid "
            "JOIN pg_class tbl ON tbl.oid = idx.indrelid "
            "WHERE tbl.relname = 'access_requests' "
            "AND pg_get_indexdef(indexrel.oid) ILIKE '%device_id%'")).scalars()
        for name in names:
            connection.execute(text(f'DROP INDEX IF EXISTS "{name}"'))
        return
    rows = connection.execute(text(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'access_requests'")).all()
    for name, definition in rows:
        if definition and "device_id" in definition.lower():
            connection.execute(text(f'DROP INDEX IF EXISTS "{name}"'))


def _restore_schema_eight_uniqueness(connection) -> None:
    """Put back the one-request-per-member-and-block rule a schema 8 database had."""
    if connection.dialect.name == "postgresql":
        connection.execute(text(
            "ALTER TABLE access_requests ADD CONSTRAINT uq_access_requests_requester_block "
            "UNIQUE (requester_id, block_id)"))
        return
    definition = connection.execute(text(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'access_requests'")).scalar()
    rewritten = definition.rstrip().removesuffix(")") + ", UNIQUE (requester_id, block_id))"
    connection.execute(text("ALTER TABLE access_requests RENAME TO access_requests_old"))
    connection.execute(text(rewritten))
    columns = [row[1] for row in connection.execute(text("PRAGMA table_info(access_requests_old)"))]
    listed = ", ".join(columns)
    connection.execute(text(
        f"INSERT INTO access_requests ({listed}) SELECT {listed} FROM access_requests_old"))
    connection.execute(text("DROP TABLE access_requests_old"))


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_schema_eight_database_gains_the_statement_quota_and_keeps_every_row(tmp_path, request, engine_kind):
    """Schema 8 gains the request basis, the statement device and the hourly quota.

    Existing requests keep an empty basis and an empty device id. A block stays one request
    per member. A statement can be one request per device.
    """
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/s8.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    engine = make_engine(place["database_url"])
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": number} for number in range(1, 9)])
    with session_factory(engine)() as db:
        seed_demo(db)
        db.commit()
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE statement_quotas"))
        _drop_device_indexes(connection)
        connection.execute(text("ALTER TABLE access_requests DROP COLUMN basis"))
        connection.execute(text("ALTER TABLE access_requests DROP COLUMN device_id"))
        _restore_schema_eight_uniqueness(connection)
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        request_columns = [column["name"] for column in inspect(connection).get_columns("access_requests")]
    assert "statement_quotas" not in tables and "basis" not in request_columns
    assert "device_id" not in request_columns

    def request_values():
        listed = ", ".join(request_columns)
        with engine.connect() as connection:
            return sorted(map(repr, connection.execute(text(f"SELECT {listed} FROM access_requests")).all()))

    before_requests = request_values()
    before = _rows(engine)
    assert sum(map(len, before.values())) > 100
    migrate(engine)
    migrate(engine)  # A second start must be a no-op.
    after = _rows(engine)
    assert after.pop("statement_quotas") == []
    after.pop("access_requests")
    before.pop("access_requests")
    assert after == before and request_values() == before_requests
    with engine.connect() as connection:
        columns = [column["name"] for column in inspect(connection).get_columns("statement_quotas")]
    assert columns == ["user_id", "count", "reset_at"]
    with engine.connect() as connection:
        names = {index["name"] for index in inspect(connection).get_indexes("access_requests")}
    assert {"uq_access_request_event", "uq_access_request_device_block", "ix_access_requests_device_id"} <= names
    with session_factory(engine)() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == list(range(1, 10))
        assert all(row.basis is None and row.device_id is None for row in db.scalars(select(AccessRequest)))
        db.add(AccessRequest(
            id="event-a", block_id="block-kept", domain="kept.example", device_name="Laptop",
            requester_id="user-jamie", reason="because", duration_minutes=60, status="pending"))
        db.commit()
        db.add(AccessRequest(
            id="event-b", block_id="block-kept", domain="kept.example", device_name="Laptop",
            requester_id="user-jamie", reason="because", duration_minutes=60, status="pending"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        for id_, device in (("stmt-a", "laptop-jamie"), ("stmt-b", "phone-jamie")):
            db.add(AccessRequest(
                id=id_, block_id="block-said", domain="said.example", device_name=device, device_id=device,
                requester_id="user-jamie", reason="because", duration_minutes=60, status="analysing",
                basis="statement"))
        db.commit()
        db.add(AccessRequest(
            id="stmt-c", block_id="block-said", domain="said.example", device_name="Laptop",
            device_id="laptop-jamie", requester_id="user-jamie", reason="because", duration_minutes=60,
            status="analysing", basis="statement"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        stored = list(db.scalars(select(AccessRequest).where(AccessRequest.block_id == "block-said")))
        assert sorted(row.device_id for row in stored) == ["laptop-jamie", "phone-jamie"]
    engine.dispose()


def _engine_on_path(url, search_path):
    """Connections use this search_path, so unqualified names resolve the way startup does."""
    engine = make_engine(url)

    @event.listens_for(engine, "connect")
    def set_search_path(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f"SET search_path TO {search_path}")
        cursor.close()

    return engine


def _side_catalog(connection):
    """Relations, constraints and rows in the schemas the upgrade must not touch."""
    relations = connection.execute(text(
        "SELECT n.nspname, c.relkind, c.relname, "
        "CASE WHEN c.relkind = 'i' THEN pg_get_indexdef(c.oid) END "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname IN ('ahead', 'other') AND c.relkind IN ('r', 'i') "
        "ORDER BY 1, 2, 3")).all()
    constraints = connection.execute(text(
        "SELECT n.nspname, rel.relname, con.conname, pg_get_constraintdef(con.oid) "
        "FROM pg_constraint con "
        "JOIN pg_class rel ON rel.oid = con.conrelid "
        "JOIN pg_namespace n ON n.oid = rel.relnamespace "
        "WHERE n.nspname IN ('ahead', 'other') "
        "ORDER BY 1, 2, 3")).all()
    rows = {
        "ahead.statement_quotas": connection.execute(text(
            "SELECT * FROM ahead.statement_quotas ORDER BY 1")).all(),
        "ahead.decoy": connection.execute(text("SELECT * FROM ahead.decoy ORDER BY 1")).all(),
        "other.access_requests": connection.execute(text(
            "SELECT * FROM other.access_requests ORDER BY 1")).all(),
    }
    return relations, constraints, rows


@pytest.mark.postgres
def test_a_schema_eight_upgrade_leaves_another_schemas_same_names_in_place(request):
    """Schema 8 in one schema is upgraded while another schema has the same table and names.

    search_path names an earlier schema first. That schema holds an index of the same name and
    its own quota table. A third schema holds access_requests with the old member and block
    uniqueness. The upgrade changes only the relation search_path resolves, records schema 9
    once, and a second start changes nothing.
    """
    place = postgres_database(request)
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    url = place["database_url"]
    bootstrap = make_engine(url)
    with bootstrap.begin() as connection:
        connection.execute(text("CREATE SCHEMA app"))
        connection.execute(text("CREATE SCHEMA ahead"))
        connection.execute(text("CREATE SCHEMA other"))
    bootstrap.dispose()

    setup = _engine_on_path(url, "app")
    with setup.begin() as connection:
        Base.metadata.create_all(connection)
        connection.execute(SchemaVersion.__table__.insert(), [{"version": number} for number in range(1, 9)])
    with session_factory(setup)() as db:
        seed_demo(db)
        db.commit()
    with setup.begin() as connection:
        connection.execute(text("DROP TABLE statement_quotas"))
        _drop_device_indexes(connection)
        connection.execute(text("ALTER TABLE access_requests DROP COLUMN basis"))
        connection.execute(text("ALTER TABLE access_requests DROP COLUMN device_id"))
        _restore_schema_eight_uniqueness(connection)
        connection.execute(text(
            "CREATE UNIQUE INDEX uq_plain_member_block ON access_requests (requester_id, block_id)"))
        connection.execute(text(
            "CREATE TABLE other.access_requests ("
            "id text PRIMARY KEY, requester_id text NOT NULL, block_id text NOT NULL)"))
        connection.execute(text(
            "INSERT INTO other.access_requests VALUES ('other-row', 'member-other', 'block-other')"))
        connection.execute(text(
            "ALTER TABLE other.access_requests "
            "ADD CONSTRAINT uq_other_event UNIQUE (requester_id, block_id)"))
        connection.execute(text(
            "CREATE UNIQUE INDEX uq_other_plain ON other.access_requests (requester_id, block_id)"))
        connection.execute(text(
            "CREATE TABLE ahead.decoy (id text PRIMARY KEY, requester_id text, block_id text)"))
        connection.execute(text(
            "CREATE UNIQUE INDEX uq_plain_member_block ON ahead.decoy (requester_id, block_id)"))
        connection.execute(text(
            "CREATE UNIQUE INDEX uq_access_requests_requester_block "
            "ON ahead.decoy (requester_id, block_id)"))
        connection.execute(text(
            "CREATE TABLE ahead.statement_quotas ("
            "user_id text PRIMARY KEY, count integer NOT NULL, reset_at timestamptz)"))
        connection.execute(text(
            "INSERT INTO ahead.statement_quotas VALUES ('member-ahead', 4, '2026-01-01 00:00:00+00')"))
        before_requests = connection.execute(text(
            "SELECT * FROM access_requests ORDER BY id")).all()
        before_side = _side_catalog(connection)
    setup.dispose()
    assert before_requests

    migrator = _engine_on_path(url, "ahead, app")
    migrate(migrator)
    migrate(migrator)
    with migrator.connect() as connection:
        after_requests = connection.execute(text(
            "SELECT * FROM app.access_requests ORDER BY id")).all()
        width = len(before_requests[0])
        assert [row[:width] for row in after_requests] == list(before_requests)
        assert all(row[width:] == (None, None) for row in after_requests)
        assert connection.execute(text("SELECT count(*) FROM app.statement_quotas")).scalar() == 0
        columns = [column["name"] for column in inspect(connection).get_columns(
            "statement_quotas", schema="app")]
        assert columns == ["user_id", "count", "reset_at"]
        indexes = set(connection.execute(text(
            "SELECT indexrel.relname FROM pg_index idx "
            "JOIN pg_class indexrel ON indexrel.oid = idx.indexrelid "
            "JOIN pg_class tbl ON tbl.oid = idx.indrelid "
            "JOIN pg_namespace nsp ON nsp.oid = tbl.relnamespace "
            "WHERE nsp.nspname = 'app' AND tbl.relname = 'access_requests'")).scalars())
        assert {"uq_access_request_event", "uq_access_request_device_block",
                "ix_access_requests_device_id"} <= indexes
        assert "uq_plain_member_block" not in indexes
        assert "uq_access_requests_requester_block" not in indexes
        uniques = set(connection.execute(text(
            "SELECT con.conname FROM pg_constraint con "
            "JOIN pg_class rel ON rel.oid = con.conrelid "
            "JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace "
            "WHERE nsp.nspname = 'app' AND rel.relname = 'access_requests' AND con.contype = 'u'")).scalars())
        assert "uq_access_requests_requester_block" not in uniques
        assert connection.execute(text(
            "SELECT version FROM app.schema_versions ORDER BY version")).scalars().all() == list(range(1, 10))
        public = connection.execute(text(
            "SELECT to_regclass('public.access_requests'), to_regclass('public.statement_quotas')")).one()
        assert public == (None, None)
        assert _side_catalog(connection) == before_side
        assert connection.execute(text(
            "SELECT id, requester_id, block_id FROM other.access_requests")).one() == (
                "other-row", "member-other", "block-other")
        assert connection.execute(text(
            "SELECT user_id, count FROM ahead.statement_quotas")).one() == ("member-ahead", 4)
    migrator.dispose()
