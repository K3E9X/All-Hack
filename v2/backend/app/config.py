"""Runtime configuration loaded from environment / .env."""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # OpenRouter
    openrouter_api_key: str = ""
    openrouter_model: str = "qwen/qwen3-coder:free"
    openrouter_fallback_models: str = (
        "meta-llama/llama-3.3-70b-instruct:free,"
        "openai/gpt-oss-120b:free,"
        "qwen/qwen3-next-80b-a3b-instruct:free"
    )
    openrouter_app_name: str = "allhack"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Storage
    data_dir: Path = Path("/data")
    # Postgres + Redis are mandatory from Phase 1 onward. Defaults match the
    # docker-compose service names so a `docker compose up` works out of the box.
    database_url: str = "postgresql://allhack:allhack@postgres:5432/allhack"
    redis_url: str = "redis://redis:6379/0"

    # MITM
    mitm_port: int = 8080

    # CORS
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def openrouter_fallback_list(self) -> List[str]:
        return [m.strip() for m in self.openrouter_fallback_models.split(",") if m.strip()]


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
