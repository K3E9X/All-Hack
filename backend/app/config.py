"""
Configuration file for the pentest application
"""
from pydantic_settings import BaseSettings
from typing import Optional, List
import os
from pathlib import Path

# Get the base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    # API Configuration
    API_TITLE: str = "Advanced Pentest Tool"
    API_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8001  # Changed from 8000 to avoid conflicts

    # CORS - can be set via ALLOWED_ORIGINS env var (comma-separated)
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"

    @property
    def cors_origins(self) -> List[str]:
        """Parse ALLOWED_ORIGINS string into list"""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(',')]

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

    # Tool Paths - relative to backend directory
    TOOLS_DIR: str = str(BASE_DIR / "app" / "tools")
    WORDLISTS_DIR: str = str(BASE_DIR / "wordlists")

    # Optional integrations
    ENABLE_BROWSER_CRAWLER: bool = True
    ENABLE_OSINT_ENRICHMENT: bool = True
    ENABLE_API_SCHEMA_COLLECTION: bool = True
    ENABLE_STABILITY_MONITORING: bool = True
    EXTERNAL_TOOL_HOOKS: list = []

    # User Agent
    USER_AGENT: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # SSL/TLS Configuration
    VERIFY_SSL: bool = False  # Disable SSL verification for pentesting (many targets have invalid certs)

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

    # AI Agent Configuration
    ANTHROPIC_API_KEY: Optional[str] = None
    ENABLE_AI_AGENT: bool = False  # Enable autonomous AI agent
    AI_AGENT_MAX_ITERATIONS: int = 10  # Max autonomous iterations

    # Notification Configuration
    # Email Notifications
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    NOTIFICATION_EMAIL_FROM: Optional[str] = None
    NOTIFICATION_EMAIL_TO: Optional[str] = None  # Can be comma-separated list

    # Webhook/Slack Notifications
    NOTIFICATION_WEBHOOK_URL: Optional[str] = None
    SLACK_WEBHOOK_URL: Optional[str] = None

    # Frontend URL for email links
    FRONTEND_URL: str = "http://localhost:5173"

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
