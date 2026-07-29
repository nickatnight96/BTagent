"""TAXII 2.1 feed client (#105 / EPIC-2 UC-2.1).

UC-2.1 promises "STIX/TAXII feeds"; before this module only the *push* half
existed (STIX bundle import + the MISP nodes). This is the *pull* half: a
focused, mock-first TAXII 2.1 client that lists collections and polls objects
from a collection since a cursor.

Why a focused client rather than the declarative runner
-------------------------------------------------------
The generic runner (:mod:`btagent_engine.integrations._declarative`) executes
one request per capability against a *statically declared* base URL, and maps a
single JSON path to an output. TAXII does not fit that shape cleanly:

* the server URL / api-root / collection id are **per-org runtime config**
  (rows in ``taxii_feeds``), not manifest constants;
* the incremental cursor lives in a *response header*
  (``X-TAXII-Date-Added-Last``), which the routing spec has no vocabulary for;
* pagination is TAXII's own ``more``/``next`` envelope, driven by the
  ``added_after`` filter.

So this is a small purpose-built client — but it keeps every property the
runner enforces:

* **Mock-first.** ``BTAGENT_MOCK_CONNECTORS`` (default *true*) serves
  deterministic fixture collections. Real HTTP happens **only** when mock mode
  is off, so the default (sovereign / air-gapped) posture makes zero egress —
  see ``backend/tests/test_zero_egress.py``.
* **Secret hygiene.** The caller passes *already-resolved* credential material;
  it is never logged, never stored, and is scrubbed out of every exception
  message this module raises (including URLs).
* **No imports from** ``btagent_agents`` / ``btagent_backend``.

TLP is deliberately **not** interpreted here. The polled objects are handed to
the existing ``stix_service`` ingest path, which derives each indicator's TLP
from its ``object_marking_refs`` exactly as the STIX-bundle import does.
"""

from __future__ import annotations

import logging
import os
from base64 import b64encode
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from btagent_engine.middleware._redaction import redact_secrets

logger = logging.getLogger("btagent.engine.integrations.taxii")

#: TAXII 2.1 media type — sent as ``Accept`` on every request.
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

#: Objects requested per page when the caller does not override it.
DEFAULT_PAGE_SIZE = 100

#: Hard ceiling on objects pulled in a single poll, so one enormous
#: collection cannot monopolise a sweep (or the ingest batch).
DEFAULT_MAX_OBJECTS = 500

#: Hard ceiling on pages walked in a single poll (belt-and-braces against a
#: server whose ``more`` flag never clears).
DEFAULT_MAX_PAGES = 10

#: Placeholder credential used in mock mode. Mock runs must never require
#: live secret material.
MOCK_CREDENTIAL = "mock-taxii-credential-not-a-real-secret"

#: Auth styles a feed may declare.
AUTH_NONE = "none"
AUTH_BEARER = "bearer"
AUTH_BASIC = "basic"
VALID_AUTH_STYLES: frozenset[str] = frozenset({AUTH_NONE, AUTH_BEARER, AUTH_BASIC})


def mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TaxiiError(RuntimeError):
    """Base class for TAXII client failures."""


class TaxiiConfigError(TaxiiError):
    """The feed configuration cannot produce a request (operator bug)."""


class TaxiiTransportError(TaxiiError):
    """The request never produced an HTTP response (DNS, TLS, timeout)."""


class TaxiiHTTPError(TaxiiError):
    """A non-2xx TAXII response."""

    def __init__(self, *, status_code: int, detail: str = "") -> None:
        message = f"TAXII server returned HTTP {status_code}"
        if detail:
            message = f"{message} — {detail}"
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TaxiiCollection:
    """One collection advertised by a TAXII api-root."""

    id: str
    title: str = ""
    description: str = ""
    can_read: bool = True
    can_write: bool = False


@dataclass(frozen=True, slots=True)
class TaxiiPollResult:
    """Everything one poll produced, plus the cursor to resume from.

    ``latest_added`` is the ``X-TAXII-Date-Added-Last`` value of the final page
    walked — the value to pass as ``added_after`` next time. It is ``None`` when
    the poll returned nothing, in which case the caller must keep its previous
    cursor (advancing on an empty poll would silently skip objects).
    """

    objects: list[dict[str, Any]] = field(default_factory=list)
    latest_added: str | None = None
    pages_fetched: int = 0
    more_available: bool = False

    @property
    def object_count(self) -> int:
        return len(self.objects)


# ---------------------------------------------------------------------------
# Mock fixtures — deterministic, offline, and cursor-aware
# ---------------------------------------------------------------------------

#: Collection id every mock feed defaults to, so a fixture feed configured
#: with "just a URL" still polls something.
MOCK_DEFAULT_COLLECTION_ID = "collection--1f2e3d4c-5b6a-4978-8899-aabbccddeeff"
MOCK_PHISHING_COLLECTION_ID = "collection--2a3b4c5d-6e7f-4801-9192-b3c4d5e6f7a8"

_TLP_AMBER_MARKING = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
_TLP_GREEN_MARKING = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"


def _indicator(
    *,
    uuid: str,
    pattern: str,
    name: str,
    description: str,
    confidence: int,
    created: str,
    marking: str | None = None,
) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid}",
        "created": created,
        "modified": created,
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "confidence": confidence,
    }
    if marking:
        obj["object_marking_refs"] = [marking]
    return obj


#: ``collection_id -> {"title", "description", "objects": [(added_iso, obj)]}``.
#: ``added`` timestamps are strictly increasing within a collection so the
#: ``added_after`` cursor filter is exercised deterministically.
_MOCK_COLLECTIONS: dict[str, dict[str, Any]] = {
    MOCK_DEFAULT_COLLECTION_ID: {
        "title": "BTagent Mock CTI — Network Indicators",
        "description": "Deterministic fixture collection served under BTAGENT_MOCK_CONNECTORS.",
        "objects": [
            (
                "2026-07-20T08:00:00.000000Z",
                _indicator(
                    uuid="6b1c2f10-1111-4a11-9c01-000000000001",
                    pattern="[ipv4-addr:value = '185.220.101.42']",
                    name="C2 egress node",
                    description="CobaltStrike C2 server observed in Operation ShadowStrike.",
                    confidence=85,
                    created="2026-07-20T07:55:00.000Z",
                    marking=_TLP_AMBER_MARKING,
                ),
            ),
            (
                "2026-07-21T08:00:00.000000Z",
                _indicator(
                    uuid="6b1c2f10-1111-4a11-9c01-000000000002",
                    pattern="[domain-name:value = 'c2-server.xyz']",
                    name="C2 domain",
                    description="Primary command-and-control domain.",
                    confidence=90,
                    created="2026-07-21T07:55:00.000Z",
                    marking=_TLP_GREEN_MARKING,
                ),
            ),
            (
                "2026-07-22T08:00:00.000000Z",
                _indicator(
                    uuid="6b1c2f10-1111-4a11-9c01-000000000003",
                    pattern=(
                        "[file:hashes.'SHA-256' = "
                        "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
                    ),
                    name="Beacon payload",
                    description="CobaltStrike beacon dropped by the loader.",
                    confidence=75,
                    created="2026-07-22T07:55:00.000Z",
                ),
            ),
        ],
    },
    MOCK_PHISHING_COLLECTION_ID: {
        "title": "BTagent Mock CTI — Phishing",
        "description": "Deterministic fixture collection served under BTAGENT_MOCK_CONNECTORS.",
        "objects": [
            (
                "2026-07-23T08:00:00.000000Z",
                _indicator(
                    uuid="7c2d3e20-2222-4b22-8d02-000000000001",
                    pattern="[url:value = 'http://login-verify.example.test/sso']",
                    name="Credential-harvest landing page",
                    description="Phishing landing page mimicking the corporate SSO portal.",
                    confidence=80,
                    created="2026-07-23T07:55:00.000Z",
                    marking=_TLP_GREEN_MARKING,
                ),
            ),
            (
                "2026-07-24T08:00:00.000000Z",
                _indicator(
                    uuid="7c2d3e20-2222-4b22-8d02-000000000002",
                    pattern="[email-addr:value = 'payroll@example-invoices.test']",
                    name="Phishing sender",
                    description="Sender address used in the invoice-themed campaign.",
                    confidence=70,
                    created="2026-07-24T07:55:00.000Z",
                    marking=_TLP_AMBER_MARKING,
                ),
            ),
        ],
    },
}


def mock_collection_ids() -> list[str]:
    """The fixture collection ids, for tests and operator docs."""
    return sorted(_MOCK_COLLECTIONS)


# ---------------------------------------------------------------------------
# Scrubbing
# ---------------------------------------------------------------------------


def scrub_secrets(text: str, *secrets: str | None) -> str:
    """Strip known credential material (and generic secret shapes) from ``text``.

    Public because the *caller* — the backend poll service — persists a
    ``last_error`` string on the feed row and must be able to guarantee the
    same hygiene this module applies to its own exceptions.
    """
    if not text:
        return text
    for secret in secrets:
        # Short values would turn common substrings into redaction noise.
        if secret and len(secret) >= 4:
            text = text.replace(secret, "[REDACTED:credential]")
    return redact_secrets(text)


class _Scrubber:
    """Removes resolved credential material from anything this module emits."""

    def __init__(self, *secrets: str | None) -> None:
        self._values = [s for s in secrets if s and len(s) >= 4]

    def __call__(self, text: str) -> str:
        return scrub_secrets(text, *self._values)


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def normalize_server_url(server_url: str) -> str:
    """Validate + canonicalise a TAXII api-root URL.

    Rejects anything that is not ``http(s)``, and refuses URLs carrying
    embedded credentials (``https://user:pass@host/``) — credentials belong in
    the secret backend behind a ``${secret:...}`` reference, never in a stored
    config string. Returns the URL without its trailing slash.
    """
    raw = (server_url or "").strip()
    if not raw:
        raise TaxiiConfigError("server_url must not be empty")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise TaxiiConfigError(f"server_url must be http(s), got scheme {parts.scheme!r}")
    if not parts.netloc:
        raise TaxiiConfigError("server_url must include a host")
    if "@" in parts.netloc:
        raise TaxiiConfigError(
            "server_url must not embed credentials; put them in Vault/AWS/env and "
            "reference them with ${secret:...}"
        )
    return raw.rstrip("/")


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------


class TaxiiClient:
    """A TAXII 2.1 api-root client scoped to one server.

    ``credential`` is *already-resolved* material (a bearer token, or
    ``user:password`` for basic auth). Resolution of ``${secret:...}``
    references is the caller's job — this class never touches the secret
    backend, never logs the value, and scrubs it from every error it raises.
    """

    def __init__(
        self,
        *,
        server_url: str,
        credential: str | None = None,
        auth_style: str = AUTH_NONE,
        timeout_seconds: float = 20.0,
        verify_tls: bool = True,
    ) -> None:
        self.server_url = normalize_server_url(server_url)
        style = (auth_style or AUTH_NONE).strip().lower()
        if style not in VALID_AUTH_STYLES:
            raise TaxiiConfigError(
                f"auth_style must be one of {sorted(VALID_AUTH_STYLES)}, got {auth_style!r}"
            )
        self.auth_style = style
        self._credential = credential or None
        self._timeout = timeout_seconds
        self._verify_tls = verify_tls
        self._scrub = _Scrubber(self._credential)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def collections(self) -> list[TaxiiCollection]:
        """List the readable collections on this api-root."""
        if mock_mode_enabled():
            return [
                TaxiiCollection(
                    id=cid,
                    title=str(spec["title"]),
                    description=str(spec["description"]),
                    can_read=True,
                    can_write=False,
                )
                for cid, spec in sorted(_MOCK_COLLECTIONS.items())
            ]

        body, _ = await self._get(f"{self.server_url}/collections/", params={})
        raw = body.get("collections", []) if isinstance(body, dict) else []
        out: list[TaxiiCollection] = []
        for item in raw:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            out.append(
                TaxiiCollection(
                    id=str(item["id"]),
                    title=str(item.get("title", "")),
                    description=str(item.get("description", "")),
                    can_read=bool(item.get("can_read", True)),
                    can_write=bool(item.get("can_write", False)),
                )
            )
        return out

    async def poll(
        self,
        collection_id: str,
        *,
        added_after: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_objects: int = DEFAULT_MAX_OBJECTS,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> TaxiiPollResult:
        """Pull objects added to ``collection_id`` after the ``added_after`` cursor.

        Walks TAXII's ``more``/``next`` pagination until the server says there
        is nothing more, or one of the ceilings is hit. The returned
        ``latest_added`` is the cursor to persist; it is ``None`` when nothing
        came back, so an empty poll leaves the caller's cursor untouched.
        """
        if not collection_id:
            raise TaxiiConfigError("collection_id must not be empty")
        page_size = max(1, min(int(page_size), 1000))
        max_objects = max(1, int(max_objects))
        max_pages = max(1, int(max_pages))

        if mock_mode_enabled():
            return self._poll_mock(collection_id, added_after=added_after, max_objects=max_objects)

        objects: list[dict[str, Any]] = []
        latest_added: str | None = None
        next_token: str | None = None
        pages = 0
        more = False

        url = f"{self.server_url}/collections/{collection_id}/objects/"
        while pages < max_pages and len(objects) < max_objects:
            params: dict[str, Any] = {"limit": min(page_size, max_objects - len(objects))}
            if added_after:
                params["added_after"] = added_after
            if next_token:
                params["next"] = next_token

            body, headers = await self._get(url, params=params)
            pages += 1
            envelope: dict[str, Any] = body if isinstance(body, dict) else {}

            page_objects = envelope.get("objects", [])
            if isinstance(page_objects, list):
                objects.extend(o for o in page_objects if isinstance(o, dict))

            page_cursor = headers.get("x-taxii-date-added-last")
            if page_cursor:
                latest_added = page_cursor

            more = bool(envelope.get("more"))
            next_token = str(envelope.get("next") or "") or None
            # No ``more``, or a server that claims more but hands back no
            # continuation token — either way there is nothing further to ask
            # for. ``more`` is still reported so the caller can see the poll
            # was cut short.
            if not more or not next_token:
                break

        if latest_added is None and objects:
            # Server omitted the header (spec says SHOULD, not MUST). Fall back
            # to the newest ``modified``/``created`` we saw so the feed still
            # makes forward progress instead of re-ingesting forever.
            latest_added = _newest_timestamp(objects)

        return TaxiiPollResult(
            objects=objects,
            latest_added=latest_added,
            pages_fetched=pages,
            more_available=more,
        )

    # ------------------------------------------------------------------ #
    # Mock path
    # ------------------------------------------------------------------ #

    def _poll_mock(
        self,
        collection_id: str,
        *,
        added_after: str | None,
        max_objects: int,
    ) -> TaxiiPollResult:
        spec = _MOCK_COLLECTIONS.get(collection_id)
        if spec is None:
            raise TaxiiHTTPError(
                status_code=404,
                detail=(
                    f"mock TAXII server has no collection {collection_id!r}; "
                    f"available: {', '.join(mock_collection_ids())}"
                ),
            )

        entries = sorted(spec["objects"], key=lambda pair: pair[0])
        cursor = (added_after or "").strip()
        fresh = [(added, obj) for added, obj in entries if not cursor or added > cursor]
        page = fresh[:max_objects]

        return TaxiiPollResult(
            objects=[dict(obj) for _, obj in page],
            latest_added=page[-1][0] if page else None,
            pages_fetched=1,
            more_available=len(fresh) > len(page),
        )

    # ------------------------------------------------------------------ #
    # Live path — reached ONLY when BTAGENT_MOCK_CONNECTORS is off
    # ------------------------------------------------------------------ #

    def _auth_headers(self) -> dict[str, str]:
        headers = {"Accept": TAXII_MEDIA_TYPE}
        if self.auth_style == AUTH_NONE:
            return headers
        credential = self._credential
        if not credential:
            raise TaxiiConfigError(
                f"auth_style={self.auth_style!r} requires credential material, but the "
                "feed's ${secret:...} reference resolved to nothing"
            )
        if self.auth_style == AUTH_BEARER:
            headers["Authorization"] = f"Bearer {credential}"
        else:  # AUTH_BASIC — credential is "user:password"
            encoded = b64encode(credential.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        return headers

    async def _get(self, url: str, *, params: dict[str, Any]) -> tuple[Any, dict[str, str]]:
        """Perform one live GET; returns ``(json_body, lower-cased headers)``."""
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on install profile
            raise TaxiiTransportError(
                "httpx is required for live TAXII polling; install it or run with "
                "BTAGENT_MOCK_CONNECTORS=true"
            ) from exc

        headers = self._auth_headers()
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify_tls) as client:
                raw = await client.get(url, headers=headers, params=params or None)
        except Exception as exc:  # transport-level: DNS/TLS/timeout
            raise TaxiiTransportError(
                self._scrub(f"TAXII request failed before a response: {exc}")
            ) from None

        response_headers = {k.lower(): v for k, v in raw.headers.items()}
        if raw.status_code >= 400:
            raise TaxiiHTTPError(
                status_code=raw.status_code,
                detail=self._scrub(raw.text[:200]),
            )
        try:
            return raw.json(), response_headers
        except Exception as exc:
            raise TaxiiHTTPError(
                status_code=raw.status_code,
                detail=self._scrub(f"response was not valid TAXII JSON: {exc}"),
            ) from None


def _newest_timestamp(objects: list[dict[str, Any]]) -> str | None:
    """Best-effort newest ``modified``/``created`` across STIX objects."""
    stamps = [
        str(obj.get("modified") or obj.get("created") or "")
        for obj in objects
        if obj.get("modified") or obj.get("created")
    ]
    return max(stamps) if stamps else None


__all__ = [
    "AUTH_BASIC",
    "AUTH_BEARER",
    "AUTH_NONE",
    "DEFAULT_MAX_OBJECTS",
    "DEFAULT_MAX_PAGES",
    "DEFAULT_PAGE_SIZE",
    "MOCK_CREDENTIAL",
    "MOCK_DEFAULT_COLLECTION_ID",
    "MOCK_PHISHING_COLLECTION_ID",
    "TAXII_MEDIA_TYPE",
    "VALID_AUTH_STYLES",
    "TaxiiClient",
    "TaxiiCollection",
    "TaxiiConfigError",
    "TaxiiError",
    "TaxiiHTTPError",
    "TaxiiPollResult",
    "TaxiiTransportError",
    "mock_collection_ids",
    "mock_mode_enabled",
    "normalize_server_url",
    "scrub_secrets",
]
