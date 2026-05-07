"""Unit tests for the hooks._redaction module and its integration with EventEmitter.

Coverage:
- Each pattern type (bearer, generic key, AWS pair, Slack, GitHub, JWT, basic-auth URL)
  is detected and replaced.
- No false positives on natural prose without an `=`/`:` separator.
- Idempotence: running redact_secrets twice yields the same output.
- Integration: EventEmitterCallback redacts BEFORE truncating to 2000 chars, so a
  secret at char 1500 is replaced with a [REDACTED:...] marker in the emitted payload.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from btagent_agents.hooks._redaction import redact_secrets
from btagent_agents.hooks.event_emitter_hook import EventEmitterCallback

# ── Pattern detection ───────────────────────────────────────────────────────


def test_bearer_token_redacted() -> None:
    text = "Authorization: Bearer abcDEF1234567890ghIJKlmno_pq.rs-tu"
    out = redact_secrets(text)
    assert "[REDACTED:bearer_token]" in out
    assert "abcDEF1234567890" not in out


def test_generic_api_key_equals() -> None:
    text = "api_key=ABCDEFGHIJKLMNOP1234567890"
    out = redact_secrets(text)
    assert "[REDACTED:credential]" in out
    assert "ABCDEFGHIJKLMNOP1234567890" not in out


def test_generic_apikey_colon_quoted() -> None:
    text = 'apikey: "sk_live_abcdef1234567890ABCD"'
    out = redact_secrets(text)
    assert "[REDACTED:credential]" in out
    assert "sk_live_abcdef1234567890ABCD" not in out


@pytest.mark.parametrize("kw", ["secret", "token", "password", "passwd", "pwd"])
def test_generic_keyword_variants(kw: str) -> None:
    text = f"{kw}=Sup3rSecretValue1234567"
    out = redact_secrets(text)
    assert "[REDACTED:credential]" in out
    assert "Sup3rSecretValue1234567" not in out


def test_aws_access_key_redacted() -> None:
    text = "Use AKIAIOSFODNN7EXAMPLE for your account."
    out = redact_secrets(text)
    assert "[REDACTED:aws_access_key_id]" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_aws_pair_redacted_within_window() -> None:
    # AKIA followed within 200 chars by a 40-char base64-ish secret.
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    text = f"id=AKIAIOSFODNN7EXAMPLE\nsk={secret}"
    out = redact_secrets(text)
    assert "[REDACTED:aws_access_key_id]" in out
    assert "[REDACTED:aws_secret_access_key]" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert secret not in out


def test_slack_token_redacted() -> None:
    text = "slack token: xoxb-1234567890-ABCDEFGhijkl"
    out = redact_secrets(text)
    assert "[REDACTED:slack_token]" in out
    assert "xoxb-1234567890-ABCDEFGhijkl" not in out


def test_github_token_redacted() -> None:
    text = "GH PAT ghp_abcdefghijklmnopqrstuvwxyz0123456789AB found in commit"
    out = redact_secrets(text)
    assert "[REDACTED:github_token]" in out
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB" not in out


def test_jwt_redacted() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    text = f"token={jwt}"
    out = redact_secrets(text)
    assert "[REDACTED:jwt]" in out
    assert jwt not in out


def test_basic_auth_url_redacted() -> None:
    text = "fetch from https://alice:hunter2@example.com/path?x=1"
    out = redact_secrets(text)
    assert "[REDACTED:basic_auth]" in out
    assert "alice:hunter2" not in out
    # Scheme and host should still be visible for debugging context.
    assert "https://" in out
    assert "@example.com/path?x=1" in out


# ── False-positive avoidance ────────────────────────────────────────────────


def test_no_false_positive_on_prose() -> None:
    text = "the password is strong and the token of trust matters"
    assert redact_secrets(text) == text


def test_no_false_positive_short_value() -> None:
    # Below 16-char threshold → not redacted.
    text = "api_key=short123"
    assert redact_secrets(text) == text


def test_empty_string_passthrough() -> None:
    assert redact_secrets("") == ""


# ── Idempotence ─────────────────────────────────────────────────────────────


def test_idempotent_bearer() -> None:
    text = "Bearer abcDEF1234567890ghIJKlmno_pq.rs-tu plus api_key=ABCDEFGHIJKLMNOP1234567890"
    once = redact_secrets(text)
    twice = redact_secrets(once)
    assert once == twice


def test_idempotent_marker_not_matched() -> None:
    # Pre-redacted text should remain stable.
    text = "value=[REDACTED:credential] and Bearer [REDACTED:bearer_token]"
    assert redact_secrets(text) == text


# ── Integration: redact-before-truncate in EventEmitter ─────────────────────


class _CapturingEmitter:
    """Minimal stand-in for RedisEmitter that records emitted payloads."""

    def __init__(self) -> None:
        self.events: list[tuple[Any, dict[str, Any]]] = []

    async def emit(self, event_type: Any, **payload: Any) -> None:  # noqa: ANN401
        self.events.append((event_type, payload))


@pytest.mark.asyncio
async def test_tool_end_redacts_before_truncation() -> None:
    """Secret at char 1500 must appear redacted, not raw, in the truncated emit."""
    emitter = _CapturingEmitter()
    cb = EventEmitterCallback(emitter, investigation_id="inv_test")  # type: ignore[arg-type]

    secret = "AKIAIOSFODNN7EXAMPLE"
    # Place AKIA at char 1500 — well before the 2000-char truncation point.
    prefix = "x" * 1500
    suffix = "y" * 1000  # Total length 2520, so truncation at 2000 will activate.
    output = prefix + secret + suffix

    run_id = uuid4()
    # on_tool_start primes the timing dict; not strictly required but realistic.
    await cb.on_tool_start({"name": "noop"}, "{}", run_id=run_id)
    await cb.on_tool_end(output, run_id=run_id)

    assert len(emitter.events) == 2
    _evt_type, payload = emitter.events[1]
    emitted = payload["output"]

    assert secret not in emitted
    assert "[REDACTED:aws_access_key_id]" in emitted
    # Truncation still applied: emitted length capped at 2000.
    assert len(emitted) <= 2000


@pytest.mark.asyncio
async def test_tool_end_passthrough_for_clean_output() -> None:
    """Outputs with no secrets must be emitted unchanged (modulo truncation)."""
    emitter = _CapturingEmitter()
    cb = EventEmitterCallback(emitter, investigation_id="inv_test")  # type: ignore[arg-type]

    output = "completely benign tool result with no credentials"
    run_id = uuid4()
    await cb.on_tool_start({"name": "noop"}, "{}", run_id=run_id)
    await cb.on_tool_end(output, run_id=run_id)

    _evt_type, payload = emitter.events[1]
    assert payload["output"] == output
