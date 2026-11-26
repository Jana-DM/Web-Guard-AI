import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_webguard.db")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest-suite")

from app.config import get_settings
from app.database.base import Base
from app.database.session import get_db
from app.main import app


@pytest.fixture(scope="session")
def test_db_engine(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("webguard_test_data")
    os.environ["UPLOAD_DIR"] = str(tmp_dir / "uploads")
    os.environ["BACKUP_DIR"] = str(tmp_dir / "backups")
    os.environ["REPORTS_DIR"] = str(tmp_dir / "reports")
    get_settings.cache_clear()

    db_file = tmp_dir / "test.db"
    eng = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db_session(test_db_engine):
    TestingSessionLocal = sessionmaker(bind=test_db_engine, autocommit=False, autoflush=False, expire_on_commit=False)
    Base.metadata.drop_all(bind=test_db_engine)
    Base.metadata.create_all(bind=test_db_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
