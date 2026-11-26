"""Initialize Web Guard AI database tables."""
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.database.base import Base
from app.database.session import engine
import app.models  # noqa: F401


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    print("Database tables initialized successfully.")


if __name__ == "__main__":
    init_db()
