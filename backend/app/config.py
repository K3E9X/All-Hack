"""
Configuration file for the pentest application
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # API Configuration
    API_TITLE: str = "Advanced Pentest Tool"
    API_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"

    # CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]

    # Scanning Configuration
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 43200  # 12 hours - Real pentests take time!
    REQUEST_TIMEOUT: int = 60  # 1 minute per request
    MAX_RETRIES: int = 5  # More retries for robustness
    BASE_TIMEOUT: int = 30
    MAX_TIMEOUT: int = 300  # 5 minutes max per operation
    BACKOFF_FACTOR: float = 2.0  # Exponential backoff

    # Persistence
    SCAN_STORAGE_DIR: str = "/tmp/pentest_scans"
    AUTO_SAVE_INTERVAL: int = 300  # Auto-save every 5 minutes

    # Tool Paths
    TOOLS_DIR: str = "/home/user/devasc-study-team/backend/app/tools"
    WORDLISTS_DIR: str = "/home/user/devasc-study-team/backend/wordlists"

    # Optional integrations
    ENABLE_BROWSER_CRAWLER: bool = True
    ENABLE_OSINT_ENRICHMENT: bool = True
    ENABLE_API_SCHEMA_COLLECTION: bool = True
    ENABLE_STABILITY_MONITORING: bool = True
    EXTERNAL_TOOL_HOOKS: list = []

    # User Agent
    USER_AGENT: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # Security Headers to check
    SECURITY_HEADERS: list = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection"
    ]

    # SQLMap Configuration
    SQLMAP_PATH: Optional[str] = None

    # Nuclei Configuration
    NUCLEI_PATH: Optional[str] = None
    NUCLEI_TEMPLATES: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
