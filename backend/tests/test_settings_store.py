"""Settings store: at-rest encryption round-trip + provider/base-url mapping.
(DB-backed read/write is integration; here we cover the pure crypto + mapping.)"""
from app import settings_store as ss


def test_encrypt_decrypt_round_trip():
    secret = "sk-live-abcdef-0123456789"
    token = ss.encrypt(secret)
    assert token != secret               # actually encrypted, not plaintext
    assert ss.decrypt(token) == secret


def test_decrypt_garbage_is_empty():
    assert ss.decrypt("not-a-valid-token") == ""


def test_provider_for_base_url():
    assert ss.provider_for_base_url("https://api.z.ai/api/paas/v4") == "zai"
    assert ss.provider_for_base_url("https://api.moonshot.cn/v1") == "moonshot"
    assert ss.provider_for_base_url("https://openrouter.ai/api/v1") == "openrouter"
    assert ss.provider_for_base_url("") == "openrouter"


def test_defaults_shape():
    for key in ("model_router", "scope", "safety", "integrations", "oob_server"):
        assert key in ss.DEFAULTS
    assert ss.DEFAULTS["safety"]["safe_mode"] is True
    for role in ("planner", "executor", "validator"):
        assert role in ss.DEFAULTS["model_router"]
