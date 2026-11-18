"""Versioned schema initialization. Future migrations must be explicit functions."""

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base, SchemaVersion

CURRENT_SCHEMA_VERSION = 9

# Schema 2 adds access decisions, leases, guest control and generated insights.
_V2_TABLES = ("settings", "leases", "device_links", "guest_passes", "guest_actions", "sightings", "insights")
# Schema 4 adds the fact cache and the list of names Nyctr itself looked up.
_V4_TABLES = ("fact_cache", "own_lookups")
# Schema 6 adds the stored verdict on a blocked name.
_V6_TABLES = ("analyses",)
# Schema 7 adds the outbound notice outbox.
_V7_TABLES = ("notices",)
# Schema 9 adds the hourly statement quota. The request basis and the statement's device are columns.
_V9_TABLES = ("statement_quotas",)
_V2_COLUMNS = {
    "observations": ("reason_codes", "source_device_id"),
    "access_requests": ("risk_score", "risk_category", "risk_factors", "decided_by", "decision_note",
                        "integration_id"),
}


def _upgrade_to_2(connection):
    """Add schema-2 tables and nullable columns without rewriting or dropping existing rows."""
    dialect = connection.dialect
    existing = set(inspect(connection).get_table_names())
    Base.metadata.create_all(connection, tables=[Base.metadata.tables[name] for name in _V2_TABLES
                                                 if name not in existing])
    for table, names in _V2_COLUMNS.items():
        present = {column["name"] for column in inspect(connection).get_columns(table)}
        for name in names:
            if name not in present:
                column = Base.metadata.tables[table].columns[name]
                kind = column.type.compile(dialect=dialect)
                connection.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {kind}'))
    connection.execute(SchemaVersion.__table__.insert().values(version=2))


def _upgrade_to_3(connection):
    """Add the table of sign-in ties. Nothing that exists is altered, so every stored row stays as it was."""
    if "device_presence" not in inspect(connection).get_table_names():
        Base.metadata.create_all(connection, tables=[Base.metadata.tables["device_presence"]])
    connection.execute(SchemaVersion.__table__.insert().values(version=3))


def _upgrade_to_4(connection):
    """Add the fact cache and Nyctr's own lookup list. Nothing that exists is altered."""
    existing = set(inspect(connection).get_table_names())
    missing = [Base.metadata.tables[name] for name in _V4_TABLES if name not in existing]
    if missing:
        Base.metadata.create_all(connection, tables=missing)
    connection.execute(SchemaVersion.__table__.insert().values(version=4))


def _upgrade_to_5(connection):
    """Add the collection holder's id and heartbeat. Existing rows gain empty columns and stay as they were."""
    present = {column["name"] for column in inspect(connection).get_columns("integrations")}
    dialect = connection.dialect
    for name in ("sync_holder", "sync_heartbeat"):
        if name not in present:
            column = Base.metadata.tables["integrations"].columns[name]
            kind = column.type.compile(dialect=dialect)
            connection.execute(text(f"ALTER TABLE integrations ADD COLUMN {name} {kind}"))
    connection.execute(SchemaVersion.__table__.insert().values(version=5))


def _upgrade_to_6(connection):
    """Add the table of stored verdicts. Nothing that exists is altered, so every stored row stays as it was."""
    if "analyses" not in inspect(connection).get_table_names():
        Base.metadata.create_all(connection, tables=[Base.metadata.tables["analyses"]])
    connection.execute(SchemaVersion.__table__.insert().values(version=6))


def _upgrade_to_7(connection):
    """Add the notice outbox. Nothing that exists is altered, so every stored row stays as it was."""
    if "notices" not in inspect(connection).get_table_names():
        Base.metadata.create_all(connection, tables=[Base.metadata.tables["notices"]])
    connection.execute(SchemaVersion.__table__.insert().values(version=7))


def _upgrade_to_8(connection):
    """Add the analysis and its claim on a request. Existing rows gain empty columns and stay as they were."""
    present = {column["name"] for column in inspect(connection).get_columns("access_requests")}
    dialect = connection.dialect
    for name in ("analysis_id", "analysis_holder", "analysis_claimed_at"):
        if name not in present:
            column = Base.metadata.tables["access_requests"].columns[name]
            kind = column.type.compile(dialect=dialect)
            connection.execute(text(f"ALTER TABLE access_requests ADD COLUMN {name} {kind}"))
    connection.execute(SchemaVersion.__table__.insert().values(version=8))


def _add_request_column(connection, name: str) -> None:
    """Add one nullable column on access_requests. A column already there is left alone."""
    present = {column["name"] for column in inspect(connection).get_columns("access_requests")}
    if name in present:
        return
    column = Base.metadata.tables["access_requests"].columns[name]
    kind = column.type.compile(dialect=connection.dialect)
    connection.execute(text(f"ALTER TABLE access_requests ADD COLUMN {name} {kind}"))


def _quote_ident(name: str) -> str:
    """Quote a database identifier that came from the catalog, not from a caller."""
    return '"' + name.replace('"', '""') + '"'


def _ensure_statement_indexes(connection) -> None:
    """The two partial unique indexes, and the device id index an upgraded database would otherwise lack."""
    existing = {index["name"] for index in inspect(connection).get_indexes("access_requests")}
    if "ix_access_requests_device_id" not in existing:
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_access_requests_device_id ON access_requests (device_id)"))
    if "uq_access_request_event" not in existing:
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_access_request_event ON access_requests "
            "(requester_id, block_id) WHERE device_id IS NULL"))
    if "uq_access_request_device_block" not in existing:
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_access_request_device_block ON access_requests "
            "(requester_id, device_id, block_id) WHERE device_id IS NOT NULL"))


def _drop_plain_event_unique(connection) -> None:
    """Drop a unique constraint or index on member and block that does not mention the device.

    The partial indexes that replace it name the device and are left in place.
    """
    if connection.dialect.name == "postgresql":
        constraints = connection.execute(text(
            "SELECT con.conname FROM pg_constraint con "
            "JOIN pg_class rel ON rel.oid = con.conrelid "
            "WHERE rel.relname = 'access_requests' AND con.contype = 'u' "
            "AND pg_get_constraintdef(con.oid) ILIKE '%requester_id%' "
            "AND pg_get_constraintdef(con.oid) ILIKE '%block_id%' "
            "AND pg_get_constraintdef(con.oid) NOT ILIKE '%device_id%'")).scalars()
        for name in constraints:
            connection.execute(text(f"ALTER TABLE access_requests DROP CONSTRAINT {_quote_ident(name)}"))
        indexes = connection.execute(text(
            "SELECT indexrel.relname, pg_get_indexdef(indexrel.oid) "
            "FROM pg_index idx "
            "JOIN pg_class indexrel ON indexrel.oid = idx.indexrelid "
            "JOIN pg_class tbl ON tbl.oid = idx.indrelid "
            "WHERE tbl.relname = 'access_requests' AND idx.indisunique AND NOT idx.indisprimary")).all()
        for name, definition in indexes:
            folded = " ".join(definition.lower().split())
            if ("requester_id" in folded and "block_id" in folded and "device_id" not in folded
                    and " where " not in folded):
                connection.execute(text(f"DROP INDEX IF EXISTS {_quote_ident(name)}"))
        return
    rows = connection.execute(text(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'access_requests'")).all()
    for name, definition in rows:
        if not definition:
            continue
        folded = " ".join(definition.lower().split())
        if (folded.startswith("create unique index") and "requester_id" in folded and "block_id" in folded
                and "device_id" not in folded and " where " not in folded):
            connection.execute(text(f"DROP INDEX IF EXISTS {_quote_ident(name)}"))


def _sqlite_table_has_event_unique(connection) -> bool:
    """A schema 8 SQLite table keeps member and block unique inside the table itself."""
    definition = connection.execute(text(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'access_requests'")).scalar() or ""
    return "unique (requester_id, block_id)" in " ".join(definition.lower().split())


def _sqlite_rebuild_requests(connection) -> None:
    """Recreate access_requests from the current model and copy every existing column.

    SQLite cannot drop a UNIQUE written into the table. Named indexes are removed first so the
    new table can create them. The autoindex that belongs to the table constraint goes with the
    old table. Rows keep the values they had. A column this build adds stays empty.
    """
    named = connection.execute(text(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'access_requests' "
        "AND sql IS NOT NULL")).scalars()
    for name in list(named):
        connection.execute(text(f"DROP INDEX IF EXISTS {_quote_ident(name)}"))
    reflected = inspect(connection)
    old_columns = [column["name"] for column in reflected.get_columns("access_requests")]
    connection.execute(text("ALTER TABLE access_requests RENAME TO access_requests_schema8"))
    Base.metadata.tables["access_requests"].create(connection)
    reflected.clear_cache()
    shared = [name for name in old_columns
              if name in {column["name"] for column in reflected.get_columns("access_requests")}]
    listed = ", ".join(shared)
    connection.execute(text(
        f"INSERT INTO access_requests ({listed}) SELECT {listed} FROM access_requests_schema8"))
    connection.execute(text("DROP TABLE access_requests_schema8"))


def _replace_request_uniqueness(connection) -> None:
    """Keep one event request per member and block, and one statement per member, device and block."""
    if connection.dialect.name == "sqlite" and _sqlite_table_has_event_unique(connection):
        _sqlite_rebuild_requests(connection)
        return
    _drop_plain_event_unique(connection)
    _ensure_statement_indexes(connection)


def _upgrade_to_9(connection):
    """Add the request basis, the statement's device and the hourly quota.

    Existing requests gain an empty basis and an empty device id and stay as they were.
    Schema 8 is unchanged by the upgrade that came before this one.
    """
    _add_request_column(connection, "basis")
    _add_request_column(connection, "device_id")
    if "statement_quotas" not in inspect(connection).get_table_names():
        Base.metadata.create_all(connection, tables=[Base.metadata.tables["statement_quotas"]])
    _replace_request_uniqueness(connection)
    connection.execute(SchemaVersion.__table__.insert().values(version=9))


def make_engine(database_url: str):
    """Create a pooled database engine with SQLite settings suitable for API tests.

    In-memory SQLite shares a connection across test threads; every SQLite
    connection enables foreign-key enforcement.
    """
    kwargs = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **kwargs)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def foreign_keys(connection, _record):
            """Enable SQLite referential-integrity checks whenever a connection is opened."""
            connection.execute("PRAGMA foreign_keys=ON")
    return engine


def migrate(engine):
    """Create the current schema in an empty database or apply explicit upgrades in order.

    PostgreSQL advisory locking serializes initialization across replicas. Unknown
    schemas and versions newer than this build raise RuntimeError instead of being altered.
    """
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            # Serialize initial schema creation across API replicas.
            connection.execute(text("SELECT pg_advisory_xact_lock(73912801)"))
        tables = inspect(connection).get_table_names()
        if "schema_versions" not in tables:
            if tables:
                raise RuntimeError("Refusing to initialize a database with an unknown existing schema")
            Base.metadata.create_all(connection)
            for number in range(1, CURRENT_SCHEMA_VERSION + 1):
                connection.execute(SchemaVersion.__table__.insert().values(version=number))
        version = connection.execute(select(SchemaVersion.version).order_by(SchemaVersion.version.desc())).scalar()
        if version == 1:
            _upgrade_to_2(connection)
            version = 2
        if version == 2:
            _upgrade_to_3(connection)
            version = 3
        if version == 3:
            _upgrade_to_4(connection)
            version = 4
        if version == 4:
            _upgrade_to_5(connection)
            version = 5
        if version == 5:
            _upgrade_to_6(connection)
            version = 6
        if version == 6:
            _upgrade_to_7(connection)
            version = 7
        if version == 7:
            _upgrade_to_8(connection)
            version = 8
        if version == 8:
            _upgrade_to_9(connection)
            version = 9
        if version != CURRENT_SCHEMA_VERSION:
            raise RuntimeError(f"Unsupported schema version {version}; expected {CURRENT_SCHEMA_VERSION}")


def session_factory(engine):
    """Build request-scoped sessions whose loaded values remain usable after commit."""
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
