"""Application settings loaded from environment variables and .env files.

All environment variables are prefixed with ``DIAGNOSE_`` to avoid collisions
with other applications running in the same process/container.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Typed, validated application configuration."""

    # ── Application ──────────────────────────────────────────────────
    APP_NAME: str = "Diagnose"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # ── PostgreSQL ───────────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://diagnose:diagnose_dev@localhost:5432/diagnose"
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 5
    DATABASE_ECHO: bool = False

    # ── Redis ────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Security & JWT ───────────────────────────────────────────────
    JWT_SECRET_KEY: str = (
        "diagnose-insecure-dev-secret-key-do-not-use-in-production-32chars"
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── API ──────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"

    # ── Hardening & Limits (M7) ──────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 120
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    MAX_REQUEST_BODY_SIZE: int = 2 * 1024 * 1024  # 2MB
    MAX_QUERY_STRING_LENGTH: int = 2048
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 100

    model_config = {
        "env_prefix": "DIAGNOSE_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton ``Settings`` instance."""
    return Settings()
