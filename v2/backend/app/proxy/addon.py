"""mitmproxy addon: persist every intercepted flow to SQLite.

Loaded by `mitmdump -s` in entrypoint.sh. Runs in the mitmproxy process,
not inside FastAPI, so it uses the synchronous storage helpers.

Configuration is taken from environment:
  - DATA_DIR : directory containing allhack.db (shared with the API).

Optional flow filtering is done by mitmproxy itself via CLI flags
(see entrypoint.sh, e.g. `--allow-hosts '^(?!.*localhost)'`).
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import List, Tuple

from mitmproxy import http

from app.proxy.storage import init_schema, insert_flow_sync

logger = logging.getLogger("allhack.proxy.addon")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "allhack.db"

# Max body bytes we store. Above this we truncate (users can re-fetch from the
# target if they need the full payload; we are a pentest bench, not an archive).
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB


class FlowLogger:
    def __init__(self) -> None:
        init_schema(DB_PATH)
        logger.info("FlowLogger ready, writing to %s", DB_PATH)

    def response(self, flow: http.HTTPFlow) -> None:
        """Called by mitmproxy once the response is complete."""
        try:
            self._persist(flow)
        except Exception:  # noqa: BLE001 - we never want to crash the proxy
            logger.exception("Failed to persist flow %s", flow.id)

    def _persist(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response

        request_headers = _headers_to_list(req.headers)
        request_body = _truncate(req.raw_content or b"")

        if resp is not None:
            response_headers = _headers_to_list(resp.headers)
            response_body = _truncate(resp.raw_content or b"")
            response_status = resp.status_code
            response_ct = resp.headers.get("content-type")
            response_size = len(resp.raw_content or b"")
            duration_ms = int((resp.timestamp_end - req.timestamp_start) * 1000) \
                if resp.timestamp_end and req.timestamp_start else None
        else:
            response_headers = []
            response_body = None
            response_status = None
            response_ct = None
            response_size = None
            duration_ms = None

        row = {
            "id": flow.id or str(uuid.uuid4()),
            "timestamp": req.timestamp_start or time.time(),
            "duration_ms": duration_ms,
            "method": req.method,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "port": req.port,
            "path": req.path,
            "url": req.pretty_url,
            "request_headers_json": json.dumps(request_headers),
            "request_body": request_body,
            "request_content_type": req.headers.get("content-type"),
            "request_size": len(req.raw_content or b""),
            "status_code": response_status,
            "response_headers_json": json.dumps(response_headers),
            "response_body": response_body,
            "response_content_type": response_ct,
            "response_size": response_size,
            "tag": None,
        }

        insert_flow_sync(DB_PATH, row)


def _headers_to_list(headers) -> List[Tuple[str, str]]:
    """mitmproxy headers preserve order and can repeat keys; keep that."""
    return [[name, value] for name, value in headers.items(multi=True)]


def _truncate(body: bytes) -> bytes:
    if len(body) <= MAX_BODY_BYTES:
        return body
    return body[:MAX_BODY_BYTES]


addons = [FlowLogger()]
