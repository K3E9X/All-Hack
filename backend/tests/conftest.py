"""Test bootstrap.

The unit tests target pure logic (classification, parsing, regexes, crypto,
scope checks) and never touch Postgres/Redis. We still set the connection env
vars before any app module is imported so that app.config.Settings constructs
cleanly at import time.
"""
import os

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
