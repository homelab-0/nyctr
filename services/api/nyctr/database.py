"""Versioned schema initialization. Future migrations must be explicit functions."""

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base, SchemaVersion

CURRENT_SCHEMA_VERSION = 1


def make_engine(database_url: str):
    kwargs = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **kwargs)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")
    return engine


def migrate(engine):
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            # Serialize initial schema creation across API replicas.
            connection.execute(text("SELECT pg_advisory_xact_lock(73912801)"))
        tables = inspect(connection).get_table_names()
        if "schema_versions" not in tables:
            if tables:
                raise RuntimeError("Refusing to initialize a database with an unknown existing schema")
            Base.metadata.create_all(connection)
            connection.execute(SchemaVersion.__table__.insert().values(version=1))
        version = connection.execute(select(SchemaVersion.version).order_by(SchemaVersion.version.desc())).scalar()
        if version != CURRENT_SCHEMA_VERSION:
            raise RuntimeError(f"Unsupported schema version {version}; expected {CURRENT_SCHEMA_VERSION}")


def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
