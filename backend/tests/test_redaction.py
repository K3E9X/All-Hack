"""Proof evidence redaction: prove access without leaking live secrets/PII."""
from app.exploit.redaction import redact_dump, redact_secrets


def test_redact_secrets_masks_sensitive_kv_keeps_names():
    env = "PATH=/usr/bin\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI1234567890abcdef\nHOME=/root"
    out = redact_secrets(env)
    assert "PATH=/usr/bin" in out                 # non-sensitive kept
    assert "HOME=/root" in out
    assert "AWS_SECRET_ACCESS_KEY=" in out         # name kept
    assert "wJalrXUtnFEMI1234567890abcdef" not in out   # value gone
    assert "(redacted)" in out


def test_redact_secrets_drops_private_key_body():
    pem = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAA\n"
           "AAAAAABBBBCCCCDDDD\n"
           "-----END OPENSSH PRIVATE KEY-----")
    out = redact_secrets(pem)
    assert "[PRIVATE KEY REDACTED]" in out
    assert "b3BlbnNzaC1rZXkt" not in out


def test_redact_secrets_masks_inline_aws_key_and_long_hex():
    body = "id_token AKIAIOSFODNN7EXAMPLE here\nhash 5f4dcc3b5aa765d61d8327deb882cf99 done"
    out = redact_secrets(body)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "5f4dcc3b5aa765d61d8327deb882cf99" not in out
    assert "(redacted)" in out


def test_redact_dump_keeps_schema_masks_values():
    dump = (
        "Database: app\nTable: users\n[2 entries]\n"
        "+----+----------+--------------------------------+\n"
        "| id | username | password                       |\n"
        "+----+----------+--------------------------------+\n"
        "| 1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf |\n"
        "| 2  | jsmith   | e10adc3949ba59abbe56e057f20f88 |\n"
        "+----+----------+--------------------------------+\n"
    )
    out = redact_dump(dump)
    # schema + count + headers preserved
    assert "Database: app" in out
    assert "Table: users" in out
    assert "[2 entries]" in out
    assert "username" in out and "password" in out
    # actual values masked
    assert "admin" not in out
    assert "jsmith" not in out
    assert "5f4dcc3b5aa765d61d8327deb882cf" not in out
    assert "(redacted)" in out


def test_redact_dump_passes_through_non_table_text():
    assert redact_dump("no table here") == "no table here"
