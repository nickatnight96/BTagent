"""Secret redaction for content emitted to subscribers (Redis pub/sub → WebSocket → browser).

Tool outputs and other free-form strings flowing through hooks may contain credentials
(API keys, bearer tokens, AWS keys, GitHub/Slack tokens, JWTs, basic-auth URLs).
This module provides a small, dependency-free redactor that replaces such tokens with
``[REDACTED:<kind>]`` markers BEFORE downstream truncation/emission.

Design notes:
- All regexes are compiled once at module load (O(n) per call over input length).
- Pure stdlib (``re`` only) — safe to import anywhere in the agents/shared layer.
- ``redact_secrets`` is idempotent: running it twice yields the same result, since
  ``[REDACTED:<kind>]`` markers do not match any of the patterns below.
- Conservative on false positives: generic key/secret/token patterns require an
  explicit ``=``/``:`` separator and a 16+ char value. Plain prose like
  "the password is strong" is left untouched.
"""

from __future__ import annotations

import re
from typing import Final

# ── Patterns ────────────────────────────────────────────────────────────────
# Order matters where overlap is possible: more specific → more generic.

_BEARER_RE: Final = re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}")

_GENERIC_KEY_RE: Final = re.compile(
    r"(?i)(?P<k>api[_-]?key|apikey|secret|token|password|passwd|pwd)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<q>['\"]?)"
    r"(?P<v>[A-Za-z0-9._/+=\-]{16,})"
    r"(?P=q)"
)

_AWS_AKID_RE: Final = re.compile(r"AKIA[0-9A-Z]{16}")

# Used to scan forward up to ~200 chars after an AKIA hit for the secret access key.
# AWS secret keys are 40-character base64-ish. The lookbehind excludes alphanumerics
# and `/`/`+` (which would indicate we're mid-token), but NOT `=` — `=` is base64
# padding that only appears at the end of a token, and is also commonly used as the
# `key=value` separator in env-style serialisations (e.g. ``AWS_SECRET_ACCESS_KEY=…``).
_AWS_SECRET_NEAR_RE: Final = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")

_SLACK_RE: Final = re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")

_GITHUB_RE: Final = re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")

_JWT_RE: Final = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

_BASIC_AUTH_URL_RE: Final = re.compile(r"(?P<scheme>https?://)[^:/\s]+:[^@/\s]+@")

# Window in characters to search after an AKIA match for the paired secret key.
_AWS_SECRET_WINDOW: Final = 200


def _redact_aws_pair(text: str) -> str:
    """Replace AWS access key IDs and best-effort the paired secret key nearby."""
    out: list[str] = []
    pos = 0
    for m in _AWS_AKID_RE.finditer(text):
        out.append(text[pos : m.start()])
        out.append("[REDACTED:aws_access_key_id]")
        pos = m.end()

        # Best-effort: scan a small window after the AKID for a 40-char base64-ish blob.
        window_end = min(len(text), pos + _AWS_SECRET_WINDOW)
        sm = _AWS_SECRET_NEAR_RE.search(text, pos, window_end)
        if sm is not None:
            out.append(text[pos : sm.start()])
            out.append("[REDACTED:aws_secret_access_key]")
            pos = sm.end()
    out.append(text[pos:])
    return "".join(out)


def _redact_basic_auth(text: str) -> str:
    return _BASIC_AUTH_URL_RE.sub(
        lambda m: f"{m.group('scheme')}[REDACTED:basic_auth]@",
        text,
    )


def _redact_generic_key(text: str) -> str:
    def _sub(m: re.Match[str]) -> str:
        return f"{m.group('k')}{m.group('sep')}{m.group('q')}[REDACTED:credential]{m.group('q')}"

    return _GENERIC_KEY_RE.sub(_sub, text)


def redact_secrets(text: str) -> str:
    """Redact credential-like tokens in a free-form string.

    Returns the input verbatim when no patterns match. Idempotent: passing the
    output back into this function yields the same string.

    The function is O(n) over the input length: each pattern performs a single
    pass and the AWS pair pass scans a fixed-size lookahead window per AKID hit.
    """
    if not text:
        return text

    # Specific patterns first — they have low false-positive risk.
    text = _BEARER_RE.sub("[REDACTED:bearer_token]", text)
    text = _redact_aws_pair(text)
    text = _SLACK_RE.sub("[REDACTED:slack_token]", text)
    text = _GITHUB_RE.sub("[REDACTED:github_token]", text)
    text = _JWT_RE.sub("[REDACTED:jwt]", text)
    text = _redact_basic_auth(text)

    # Generic key/secret/token=value patterns last — broadest, applied to whatever remains.
    text = _redact_generic_key(text)

    return text


__all__ = ["redact_secrets"]
