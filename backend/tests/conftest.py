"""Test bootstrap.

The unit tests target pure logic (classification, parsing, regexes, crypto,
scope checks) and never touch Postgres/Redis. We still set the connection env
vars before any app module is imported so that app.config.Settings constructs
cleanly at import time.
"""
import os
import tempfile

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
# A writable data dir so importing app.config never tries to mkdir "/data"
# (which fails on a non-root CI runner).
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="syphax-test-"))
