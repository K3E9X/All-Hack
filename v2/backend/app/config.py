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
    openrouter_app_name: str = "allhack"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Storage
    data_dir: Path = Path("/data")

    # MITM
    mitm_port: int = 8080

    # CORS
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def sqlite_path(self) -> Path:
        return self.data_dir / "allhack.db"


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
