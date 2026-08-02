"""E10 / P4.4: HTTP Basic auth headers must be scrubbed from logged requests.

The declarative runner emits ``Authorization: Basic <base64(user:pass)>`` for
``auth.style=basic``. The base64 blob decodes straight back to the credential,
so it must be redacted from any logged request line — previously only the
URL-embedded ``user:pass@host`` form was covered.
"""

from __future__ import annotations

from base64 import b64encode

from btagent_engine.middleware._redaction import redact_secrets


def test_basic_auth_header_blob_is_redacted():
    token = b64encode(b"admin:s3cr3t-p@ssw0rd").decode()
    line = f"GET /v1/things Authorization: Basic {token}"
    out = redact_secrets(line)
    assert token not in out
    assert "s3cr3t" not in out
    assert "[REDACTED:basic_auth]" in out


def test_basic_auth_redaction_is_idempotent():
    token = b64encode(b"user:password").decode()
    once = redact_secrets(f"Basic {token}")
    assert redact_secrets(once) == once


def test_url_embedded_basic_auth_still_redacted():
    """The other Basic-auth shape (userinfo in the URL) is unaffected."""
    out = redact_secrets("connecting to https://svc:hunter2@taxii.example.test/api1")
    assert "hunter2" not in out
    assert "[REDACTED:basic_auth]" in out
