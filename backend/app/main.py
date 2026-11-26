from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.config import get_settings
from app.core.logging import configure_logging
from app.core.middleware import SecurityHeadersMiddleware
from app.database.base import Base
from app.database.session import engine
import app.models  # noqa: F401


@asynccontextmanager
async def lifespan(_app: FastAPI):
    configure_logging()
    settings = get_settings()
    settings.ensure_storage_dirs()
    Base.metadata.create_all(bind=engine)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.APP_NAME,
        version="1.0.0",
        description="AI-Powered Continuous Cybersecurity Intelligence and Vulnerability Assessment Platform",
        lifespan=lifespan,
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.get("/health", tags=["Health"])
    def health_check():
        return {"status": "healthy", "service": settings.APP_NAME}

    return app


app = create_app()
