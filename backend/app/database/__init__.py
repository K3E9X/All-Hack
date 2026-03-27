"""
Database module for All-Hack
SQLite with SQLAlchemy ORM - upgradable to PostgreSQL
"""

from .connection import engine, SessionLocal, get_db, init_db
from .models import Base, Scan, Finding, AgentMemory, ExploitChain, UserSettings

__all__ = [
    "engine",
    "SessionLocal",
    "get_db",
    "init_db",
    "Base",
    "Scan",
    "Finding",
    "AgentMemory",
    "ExploitChain",
    "UserSettings"
]
