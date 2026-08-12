"""The proof a validator proposes is a request this tool will actually send.

So it is validated like operator input, not like model output: read-only verb,
same host as the finding, nothing that reads like a write. Every rejection test
here describes a request that must never leave the machine.
"""
from __future__ import annotations

import pytest

from app.validation.llm_judge import PROOF_METHODS, parse_judgment, parse_proof

TARGET = "https://app.example.com/login"


def proof(**over):
    base = {"method": "GET", "url": "https://app.example.com/wp-json/wp/v2/users",
            "expect": "\"slug\":\"admin\"", "why": "route enumerates users"}
    base.update(over)
    return base


# ---- Accepted ----

def test_read_only_same_host_proof_is_accepted():
    p = parse_proof(proof(), TARGET)
    assert p is not None
    assert p["method"] == "GET"
    assert p["expect"] == "\"slug\":\"admin\""


def test_head_is_allowed():
    assert parse_proof(proof(method="head"), TARGET)["method"] == "HEAD"


def test_target_given_as_a_bare_host_still_matches():
    assert parse_proof(proof(), "app.example.com") is not None


# ---- Rejected: verb ----

@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", ""])
def test_state_changing_verbs_are_refused(method):
    assert parse_proof(proof(method=method), TARGET) is None


def test_policy_is_read_only():
    assert PROOF_METHODS == {"GET", "HEAD"}


# ---- Rejected: host ----

def test_other_host_is_refused():
    """The whole point of scope is that a finding on A cannot justify a request to B."""
    assert parse_proof(proof(url="https://evil.example/steal"), TARGET) is None


def test_subdomain_is_not_the_same_host():
    assert parse_proof(proof(url="https://admin.app.example.com/x"), TARGET) is None


def test_host_comparison_ignores_case():
    assert parse_proof(proof(url="https://APP.EXAMPLE.COM/x"), TARGET) is not None


@pytest.mark.parametrize("url", [
    "", "not-a-url", "/relative/path", "ftp://app.example.com/x",
    "file:///etc/passwd", "javascript:alert(1)",
])
def test_non_http_urls_are_refused(url):
    assert parse_proof(proof(url=url), TARGET) is None


# ---- Rejected: looks like a write ----

@pytest.mark.parametrize("path", [
    "/admin/delete?id=1", "/users/remove", "/api/reset-password",
    "/session/logout", "/cache/purge", "/account/deactivate",
])
def test_mutating_paths_are_refused(path):
    """A GET can still change state. When it reads like a write, refuse it."""
    assert parse_proof(proof(url=f"https://app.example.com{path}"), TARGET) is None


def test_mutating_query_key_is_refused():
    assert parse_proof(
        proof(url="https://app.example.com/x?action=drop_table"), TARGET) is None


# ---- Rejected: useless expectation ----

@pytest.mark.parametrize("expect", ["", " ", "ok", "200", "a"])
def test_short_expectations_are_refused(expect):
    """A substring that matches almost any page proves nothing."""
    assert parse_proof(proof(expect=expect), TARGET) is None


def test_expectation_is_truncated_not_rejected():
    p = parse_proof(proof(expect="x" * 500), TARGET)
    assert p is not None and len(p["expect"]) == 200


# ---- Malformed ----

@pytest.mark.parametrize("raw", [None, "", [], 42, {"method": "GET"}, {}])
def test_malformed_proofs_yield_nothing(raw):
    assert parse_proof(raw, TARGET) is None


# ---- The judgment still parses without a proof ----

def test_judgment_without_a_proof_is_still_valid():
    j = parse_judgment('{"verdict":"false_positive","confidence":0.9,"reason":"noise"}')
    assert j["verdict"] == "false_positive"
    assert j["proof"] is None


def test_judgment_carries_the_proof_through():
    j = parse_judgment(
        '{"verdict":"likely","confidence":0.7,"quote":"x","reason":"r",'
        '"proof":{"method":"GET","url":"https://app.example.com/a",'
        '"expect":"admin-token","why":"w"}}'
    )
    assert parse_proof(j["proof"], TARGET)["url"].endswith("/a")
