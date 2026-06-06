"""CORS probe verdicts (async). A fake SafePoC returns crafted response headers
so we exercise the verdict logic without any network."""
from app.analysis.cors import _probe
from app.validation.safe_poc import SafeResponse

EVIL = "https://evil-abcd.example"


class FakeSafe:
    def __init__(self, headers):
        self._headers = headers

    async def fetch(self, url, *, method="GET", headers=None):
        return SafeResponse(status_code=200, headers=self._headers, text="ok", url=url)


async def _verdict(headers):
    return await _probe(FakeSafe(headers), "http://t/api/data", EVIL)


async def test_reflected_origin_with_credentials_is_high():
    v = await _verdict({"access-control-allow-origin": EVIL,
                        "access-control-allow-credentials": "true"})
    sev, status, conf, poc = v
    assert sev == "high" and status == "confirmed"


async def test_reflected_origin_without_credentials_is_medium():
    v = await _verdict({"access-control-allow-origin": EVIL})
    assert v[0] == "medium" and v[1] == "likely"


async def test_wildcard_with_credentials_is_low():
    v = await _verdict({"access-control-allow-origin": "*",
                        "access-control-allow-credentials": "true"})
    assert v[0] == "low"


async def test_wildcard_only_is_info():
    v = await _verdict({"access-control-allow-origin": "*"})
    assert v[0] == "info"


async def test_no_cors_header_is_none():
    assert await _verdict({"content-type": "application/json"}) is None


async def test_unrelated_origin_is_none():
    # Server echoes its own fixed origin, not ours -> not a finding.
    assert await _verdict({"access-control-allow-origin": "https://trusted.example"}) is None
