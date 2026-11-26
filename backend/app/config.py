from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "Web Guard AI"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    SECRET_KEY: str = "dev-secret-key-change-before-production-0001"
    ENCRYPTION_KEY: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 10080

    DATABASE_URL: str = "sqlite:///./webguard.db"

    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"
    CELERY_TASK_ALWAYS_EAGER: bool = True

    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"

    UPLOAD_DIR: str = "./uploads"
    BACKUP_DIR: str = "./backups"
    REPORTS_DIR: str = "./reports_output"
    MAX_UPLOAD_SIZE_MB: int = 250

    SCAN_HTTP_TIMEOUT_SECONDS: float = 8.0
    SCAN_MAX_REDIRECTS: int = 3
    SCAN_MAX_ENDPOINTS: int = 40
    SCAN_RATE_LIMIT_PER_MINUTE: int = 30
    ALLOW_LOCALHOST_SCANNING: bool = False

    NVD_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    INTELLIGENCE_SYNC_HOUR_UTC: int = 2

    LLM_PROVIDER: str = "none"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    def ensure_storage_dirs(self) -> None:
        for path_str in (self.UPLOAD_DIR, self.BACKUP_DIR, self.REPORTS_DIR):
            Path(path_str).mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_storage_dirs()
    return settings
