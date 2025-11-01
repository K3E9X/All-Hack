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
    SCAN_TIMEOUT: int = 3600  # 1 hour
    REQUEST_TIMEOUT: int = 30
    MAX_RETRIES: int = 3

    # Tool Paths
    TOOLS_DIR: str = "/home/user/devasc-study-team/backend/app/tools"
    WORDLISTS_DIR: str = "/home/user/devasc-study-team/backend/wordlists"

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
