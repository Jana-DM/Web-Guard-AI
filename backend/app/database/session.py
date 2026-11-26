from collections.abc import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def _create_engine():
    settings = get_settings()
    url = settings.DATABASE_URL
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    eng = create_engine(url, connect_args=connect_args, pool_pre_ping=True, future=True)

    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return eng


engine = _create_engine()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
