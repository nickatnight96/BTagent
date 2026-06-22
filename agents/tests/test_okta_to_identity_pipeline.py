"""End-to-end pipe test: Okta MCP connector → Identity Hunt detectors (#100 + #116).

Proves the contract the connector slice was built to satisfy: the Okta
fixtures flow through the connector's mock path, the normaliser maps them
to :class:`IdentityEvent` / :class:`OAuthGrant`, and the pure-logic
detectors from :mod:`btagent_shared.hunt.identity` light up with the
expected findings.

This is the integration smoke test that justifies declaring the slice
"done" — without it, the connector and the detectors would each pass
their own unit tests while the join between them silently rotted.
"""

from __future__ import annotations

import pytest
from btagent_shared.hunt.identity import (
    detect_dormant_app_reactivation,
    detect_federation_trust_modification,
    detect_mfa_fatigue,
    detect_oauth_token_replay,
    run_all_detectors,
)
from btagent_shared.types.identity_hunt import (
    IdentityEvent,
    IdentityEventKind,
    OAuthGrant,
)

from btagent_agents.mcp.servers.okta_mcp import (
    OktaMCPServer,
    normalise_oauth_grant,
    normalise_system_log_event,
)


@pytest.fixture
def okta_server() -> OktaMCPServer:
    return OktaMCPServer(mock_mode=True)


async def _fetch_events(srv: OktaMCPServer) -> list[IdentityEvent]:
    env = await srv.okta_system_log_search(
        start="2026-06-18T00:00:00Z",
        end="2026-06-19T00:00:00Z",
    )
    return [IdentityEvent.model_validate(e) for e in env["events"]]


async def _fetch_grants(srv: OktaMCPServer) -> list[OAuthGrant]:
    env = await srv.okta_list_oauth_grants()
    return [OAuthGrant.model_validate(g) for g in env["grants"]]


# ---------------------------------------------------------------------------
# Token replay — two ASNs, same session/token, within window
# ---------------------------------------------------------------------------


async def test_token_replay_fires_for_okta_fixture(
    okta_server: OktaMCPServer,
) -> None:
    events = await _fetch_events(okta_server)
    # Sanity: both replay events normalised
    replay_evts = [
        e
        for e in events
        if e.kind in {IdentityEventKind.TOKEN_ISSUED, IdentityEventKind.TOKEN_REFRESH}
        and e.session_id == "ext_sess_fixture_replay_001"
    ]
    assert len(replay_evts) == 2

    findings = detect_oauth_token_replay(
        events,
        window_minutes=30,
        min_asn_count=2,
    )
    assert findings, "token replay detector did not fire on the Okta fixture"
    # Should be for alice and reference distinct ASNs (AS15169 + AS8075)
    titles = " ".join(f.title for f in findings)
    assert "alice@example.com" in titles
    asns = set()
    for f in findings:
        for asn in f.evidence.get("distinct_asns", []):
            asns.add(asn)
    assert {"AS15169", "AS8075"}.issubset(asns)


# ---------------------------------------------------------------------------
# MFA fatigue — 3 denials then approval
# ---------------------------------------------------------------------------


async def test_mfa_fatigue_fires_for_okta_fixture(
    okta_server: OktaMCPServer,
) -> None:
    events = await _fetch_events(okta_server)
    findings = detect_mfa_fatigue(events, denial_threshold=3, window_minutes=10)
    assert findings, "MFA fatigue detector did not fire on the Okta fixture"
    bob_findings = [f for f in findings if f.entity_value == "bob@example.com"]
    assert bob_findings, "expected fatigue finding to be on bob@example.com"
    assert bob_findings[0].evidence["denial_count"] >= 3


# ---------------------------------------------------------------------------
# Federation modification — always flagged critical
# ---------------------------------------------------------------------------


async def test_federation_trust_mod_fires_for_okta_fixture(
    okta_server: OktaMCPServer,
) -> None:
    events = await _fetch_events(okta_server)
    findings = detect_federation_trust_modification(events)
    assert findings, "federation trust detector did not fire on the Okta fixture"
    assert findings[0].severity == "critical"


# ---------------------------------------------------------------------------
# Dormant app reactivation — pairs the dormant grant with its reactivation
# ---------------------------------------------------------------------------


async def test_dormant_app_reactivation_fires_for_okta_fixture(
    okta_server: OktaMCPServer,
) -> None:
    events = await _fetch_events(okta_server)
    grants = await _fetch_grants(okta_server)
    findings = detect_dormant_app_reactivation(grants, events, idle_days=90)
    assert findings, "dormant-app detector did not fire on the Okta fixture"
    f = findings[0]
    assert f.evidence["app_id"] == "dormant_legacy_addon"
    assert f.evidence["idle_days"] >= 90


# ---------------------------------------------------------------------------
# End-to-end: run_all_detectors against connector output
# ---------------------------------------------------------------------------


async def test_run_all_detectors_against_okta_connector(
    okta_server: OktaMCPServer,
) -> None:
    events = await _fetch_events(okta_server)
    grants = await _fetch_grants(okta_server)
    results = run_all_detectors(events, grants)
    rule_ids = {r.rule_id for r in results}
    # The fixture is designed to light up at least these four detectors.
    expected = {
        "identity.oauth_token_replay",
        "identity.mfa_fatigue",
        "identity.federation_trust_modification",
        "identity.dormant_app_reactivation",
    }
    assert expected.issubset(rule_ids), (
        f"expected detectors {expected - rule_ids} missing from {rule_ids}"
    )


# ---------------------------------------------------------------------------
# Pure-normaliser fast paths (no connector needed)
# ---------------------------------------------------------------------------


def test_pure_normaliser_round_trips_through_pydantic() -> None:
    """The IdentityEvent / OAuthGrant model_dump → model_validate cycle is
    used by every downstream subscriber (Redis pub/sub, plugin state). Round
    trip must be lossless for the fields the detectors read."""
    from btagent_agents.mcp.servers._okta_fixtures import (
        OKTA_FIXTURE_OAUTH_GRANTS,
        OKTA_FIXTURE_SYSTEM_LOG,
    )

    for raw in OKTA_FIXTURE_SYSTEM_LOG:
        ev = normalise_system_log_event(raw, org_id="x")
        if ev is None:
            continue
        dumped = ev.model_dump(mode="json")
        reread = IdentityEvent.model_validate(dumped)
        assert reread.kind is ev.kind
        assert reread.principal_id == ev.principal_id
        assert reread.session_id == ev.session_id
        assert reread.token_id == ev.token_id
        assert reread.geo.asn == ev.geo.asn

    for raw in OKTA_FIXTURE_OAUTH_GRANTS:
        g = normalise_oauth_grant(raw, org_id="x")
        dumped = g.model_dump(mode="json")
        reread = OAuthGrant.model_validate(dumped)
        assert reread.principal_id == g.principal_id
        assert reread.app_id == g.app_id
        assert reread.consent_type is g.consent_type
