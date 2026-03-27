"""
Database connection and session management
"""

import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

# Database path - configurable via environment
DB_PATH = os.getenv("ALLHACK_DB_PATH", str(Path(__file__).parent.parent.parent / "data" / "allhack.db"))

# Ensure data directory exists
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

# SQLite connection with WAL mode for better concurrency
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # SQLite specific
    echo=False,  # Set True for SQL debugging
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency for FastAPI endpoints"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    from sqlalchemy import text
    from .models import Base

    # Enable WAL mode for better concurrent reads
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA synchronous=NORMAL"))
        conn.execute(text("PRAGMA cache_size=10000"))
        conn.execute(text("PRAGMA temp_store=MEMORY"))
        conn.commit()

    Base.metadata.create_all(bind=engine)
    print(f"[Database] Initialized at {DB_PATH}")
