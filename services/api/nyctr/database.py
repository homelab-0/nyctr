"""Versioned schema initialization. Future migrations must be explicit functions."""

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base, SchemaVersion

CURRENT_SCHEMA_VERSION = 2

# Schema 2 adds access decisions, leases, guest control and generated insights.
_V2_TABLES = ("settings", "leases", "device_links", "guest_passes", "guest_actions", "sightings", "insights")
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
        if version != CURRENT_SCHEMA_VERSION:
            raise RuntimeError(f"Unsupported schema version {version}; expected {CURRENT_SCHEMA_VERSION}")


def session_factory(engine):
    """Build request-scoped sessions whose loaded values remain usable after commit."""
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
