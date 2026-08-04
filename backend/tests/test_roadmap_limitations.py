"""ROADMAP.md's "Known Limitations" table has to match the code.

A limitations table is the one piece of documentation a reader trusts to be
pessimistic. This one had rotted in the worst direction: it under-described
the product in six of nine rows, telling anyone who read it that BTagent was
single-tenant, had no SSO, could not revoke a refresh token, could not export
a PDF, and had no automated feed ingestion. All five had shipped. A reader
making an adoption or security decision off that table would have been wrong
about things that matter.

Nobody was careless — a limitations table has no natural moment where someone
is forced to revisit it. Shipping the feature is the moment, and nothing
connected the two. This file connects them.

Two directions are checked, and both matter:

* **Retired claims stay retired.** For each limitation that shipped, assert
  the code fact that retires it *and* that the phrase is gone from the table.
  If the feature is ever ripped out, the code assertion fails and someone has
  to decide deliberately; if the stale sentence is pasted back, the phrase
  assertion fails.
* **Live claims stay true.** The remaining rows describe things the code
  genuinely still does not do. Each is tied to the evidence that it is still a
  limitation, so a row cannot outlive the gap it describes — which is exactly
  how the last six got stale.

Deliberately *not* checked: prose quality, row ordering, or the "Planned Fix"
column. Those are judgement, and a test that pins judgement just gets deleted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_ROADMAP = _REPO / "docs" / "ROADMAP.md"
_PLAN = _REPO / "docs" / "DEPLOYMENT_PLAN.md"
_BACKEND = _REPO / "backend" / "btagent_backend"


@pytest.fixture(scope="module")
def limitations_section() -> str:
    """The "Known Limitations" section, up to the next top-level heading."""
    text = _ROADMAP.read_text(encoding="utf-8")
    start = text.find("## Known Limitations")
    assert start != -1, "ROADMAP.md no longer has a 'Known Limitations' section"
    rest = text[start + len("## Known Limitations") :]
    end = rest.find("\n## ")
    return rest if end == -1 else rest[:end]


# ---------------------------------------------------------------------------
# Retired limitations: the code fact, and the absence of the stale phrase.
#
# `phrase` is matched case-insensitively against the section. Keep them close
# to what the old table literally said — the point is to catch a revert or a
# copy-paste from an old release note, not to police wording.
# ---------------------------------------------------------------------------


def _read(*parts: str) -> str:
    return (_REPO.joinpath(*parts)).read_text(encoding="utf-8")


def test_refresh_tokens_rotate_and_can_be_revoked(limitations_section: str):
    jwt_src = _read("backend", "btagent_backend", "auth", "jwt.py")
    revocation_src = _read("backend", "btagent_backend", "auth", "revocation.py")
    assert "family_id" in jwt_src, "refresh-token families gone — rotation may be broken"
    assert "revoke_user_tokens" in revocation_src
    assert "cannot be revoked" not in limitations_section.lower()


def test_saml_and_oidc_exist(limitations_section: str):
    assert (_BACKEND / "auth" / "saml.py").is_file()
    assert (_BACKEND / "auth" / "oidc.py").is_file()
    assert (_BACKEND / "api" / "v1" / "sso.py").is_file()
    assert "no saml or oidc" not in limitations_section.lower()


def test_pdf_export_exists(limitations_section: str):
    reports_src = _read("backend", "btagent_backend", "api", "v1", "reports.py")
    assert 'format: Literal["pdf"]' in reports_src, "the PDF export route changed shape"
    assert (_BACKEND / "services" / "report_pdf.py").is_file()
    assert "no pdf export" not in limitations_section.lower()


def test_multi_tenancy_is_real(limitations_section: str):
    """Not just "org_id exists" — that the routes actually scope by it."""
    models_src = _read("backend", "btagent_backend", "db", "models.py")
    assert "org_id" in models_src
    scoping_src = _read("backend", "btagent_backend", "auth", "scoping.py")
    assert "def can_access_investigation" in scoping_src, (
        "the shared tenant predicate is gone; multi-tenancy may have regressed"
    )
    lowered = limitations_section.lower()
    assert "single-tenant only" not in lowered
    assert "share one organization" not in lowered


def test_taxii_feed_ingestion_is_automated(limitations_section: str):
    assert (_BACKEND / "api" / "v1" / "taxii_feeds.py").is_file()
    worker_src = _read("backend", "btagent_backend", "scheduler", "worker.py")
    assert "taxii_feed_poll_sweep" in worker_src, "the TAXII poll cron is no longer registered"
    lowered = limitations_section.lower()
    assert "manual stix import only" not in lowered
    assert "no automated feed ingestion" not in lowered


def test_cors_is_not_wildcarded(limitations_section: str):
    main_src = _read("backend", "btagent_backend", "main.py")
    # Explicit allow-lists, not "*".
    assert 'allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]' in main_src
    assert 'allow_headers=["Content-Type", "Authorization", "X-Request-ID"]' in main_src
    assert "wildcard methods/headers" not in limitations_section.lower()


def test_seed_passwords_are_not_trivial(limitations_section: str):
    bootstrap_src = _read("backend", "btagent_backend", "auth", "bootstrap.py")
    assert "secrets.token_urlsafe" in bootstrap_src, (
        "seed users no longer get a random password outside test mode"
    )
    assert "trivial passwords" not in limitations_section.lower()


# ---------------------------------------------------------------------------
# Live limitations: still true, and still listed.
# ---------------------------------------------------------------------------


def test_connector_count_matches_the_registry(limitations_section: str):
    """The table quotes a number. Numbers in prose rot faster than sentences."""
    from btagent_agents.mcp import discovery

    discovery._ensure_servers_loaded()
    registered = len(discovery._SERVER_CLASSES)

    match = re.search(r"All (\d+) registered connectors", limitations_section)
    assert match, "the MCP connector row no longer states a count"
    assert int(match.group(1)) == registered, (
        f"ROADMAP says {match.group(1)} connectors, registry has {registered}"
    )


def test_connectors_really_are_still_mock_first():
    """If live paths stop raising, the row above becomes the stale one."""
    src = _read("agents", "btagent_agents", "mcp", "servers", "splunk_mcp.py")
    assert "NotImplementedError" in src, (
        "a connector's live path no longer raises — if live wiring landed, "
        "update the MCP Connectors row instead of deleting this assertion"
    )


def test_detection_validation_is_still_sandbox_only(limitations_section: str):
    src = _read("backend", "btagent_backend", "services", "detection_emulation_service.py")
    assert "sandbox" in src.lower(), "the sandbox-only guard is gone from the emulation service"
    assert "sandbox-only" in limitations_section.lower()


def test_ioc_graph_backend_is_still_absent(limitations_section: str):
    """The one original row that was always accurate."""
    for path in (_BACKEND / "services").glob("*.py"):
        assert "neo4j" not in path.read_text(encoding="utf-8").lower(), (
            f"{path.name} references a graph backend — the IOC Graphs row is now stale"
        )
    assert "no graph database" in limitations_section.lower()


# ---------------------------------------------------------------------------
# Guard the guard.
# ---------------------------------------------------------------------------


def test_the_section_was_actually_found(limitations_section: str):
    """A lookup that silently returned "" would make every phrase check pass."""
    assert len(limitations_section) > 500
    assert "| Area | Limitation | Planned Fix |" in limitations_section


# ---------------------------------------------------------------------------
# DEPLOYMENT_PLAN.md Section 2 carried the same stale rows, from the same
# cause. Same treatment: an item cannot sit in the open list once its code
# has shipped.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def plan_section_2() -> str:
    text = _PLAN.read_text(encoding="utf-8")
    start = text.find("## Section 2 — Production readiness")
    assert start != -1, "DEPLOYMENT_PLAN.md no longer has a Section 2"
    rest = text[start:]
    end = rest.find("\n## Section 3")
    section = rest if end == -1 else rest[:end]
    assert len(section) > 500, "Section 2 lookup returned almost nothing"
    return section


@pytest.mark.parametrize(
    "item,evidence",
    [
        ("JWT revocation + refresh rotation", ("backend/btagent_backend/auth/revocation.py",)),
        ("Hardened CORS default", ("backend/btagent_backend/main.py",)),
        (
            "Deep health checks + graceful shutdown",
            ("backend/btagent_backend/api/v1/health.py",),
        ),
        (
            "SSO (SAML 2.0 / OIDC), MFA (TOTP)",
            ("backend/btagent_backend/auth/saml.py", "backend/btagent_backend/api/v1/mfa.py"),
        ),
        ("PDF report export", ("backend/btagent_backend/services/report_pdf.py",)),
    ],
)
def test_shipped_plan_items_are_listed_as_closed(
    item: str, evidence: tuple[str, ...], plan_section_2: str
):
    """Shipped work must appear under "Closed", struck through, not as open."""
    for rel in evidence:
        assert (_REPO / rel).is_file(), (
            f"{rel} is gone — if {item!r} was reverted, move it back to the open "
            "table deliberately rather than deleting this case"
        )
    closed_at = plan_section_2.find("Closed since this table was written")
    assert closed_at != -1, "the Closed subsection is gone from Section 2"
    assert item in plan_section_2[closed_at:], (
        f"{item!r} has shipped but is not listed under Closed in Section 2"
    )


def test_plan_connector_count_matches_the_registry(plan_section_2: str):
    from btagent_agents.mcp import discovery

    discovery._ensure_servers_loaded()
    match = re.search(r"All (\d+) registered MCP connectors", plan_section_2)
    assert match, "the P0 connector row no longer states a count"
    assert int(match.group(1)) == len(discovery._SERVER_CLASSES)
