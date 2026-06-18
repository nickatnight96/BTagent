"""Seeded fixture events for Identity Hunt golden tests (Phase 6 #116).

All fixtures are deterministic (fixed timestamps, no randomness) so golden
tests are repeatable and suitable for CI. No network, DB, or LLM calls.

Fixture catalogue
-----------------
token_replay_events()
    A session_id that appears from AS15169 (Google) then AS8075 (Microsoft)
    within 20 minutes — should trigger oauth_token_replay.

clean_token_events()
    Same session_id, same ASN, two events — should NOT trigger token replay.

dormant_grant_and_events()
    An OAuthGrant with last_used 100 days before the activity event — should
    trigger dormant_app_reactivation.

active_grant_and_events()
    An OAuthGrant with last_used 10 days before activity — should NOT trigger.

impossible_travel_events()
    Two LOGIN_SUCCESS for the same principal: London then New York 5 minutes
    apart (~5700 km, ~68 000 km/h) — should trigger impossible_travel.

possible_travel_events()
    Two LOGIN_SUCCESS 8 hours apart (London → NY) — should NOT trigger.

sp_credential_addition_events()
    A CREDENTIAL_ADDED event with app_id populated — should trigger.

non_sp_credential_addition_events()
    A CREDENTIAL_ADDED event with no app_id and no SP marker in principal_id
    — should NOT trigger.

federation_trust_modification_events()
    A FEDERATION_TRUST_MODIFIED event — should trigger.

mfa_fatigue_events()
    4 MFA_DENIED then 1 MFA_APPROVED within 8 minutes — should trigger.

mfa_clean_events()
    2 MFA_DENIED then 1 MFA_APPROVED (below threshold of 3) — should NOT.
"""

from __future__ import annotations

from datetime import UTC, datetime

from btagent_shared.types.identity_hunt import (
    GeoLocation,
    IdentityEvent,
    IdentityEventKind,
    IdentityProvider,
    OAuthConsentType,
    OAuthGrant,
)

_ORG = "org_01FIXTURE"
_PROVIDER = IdentityProvider.ENTRA

# ── helpers ────────────────────────────────────────────────────────────────


def _dt(iso: str) -> datetime:
    """Parse a UTC ISO timestamp string to a timezone-aware datetime."""
    return datetime.fromisoformat(iso).replace(tzinfo=UTC)


# ── Token replay ───────────────────────────────────────────────────────────


def token_replay_events() -> list[IdentityEvent]:
    """Same session_id / token_id observed from two different ASNs within 20 min."""
    session = "session_TOKEN_REPLAY_FIXTURE_001"
    token = "jti_TOKEN_REPLAY_FIXTURE_001"
    return [
        IdentityEvent(
            id="evt_replay_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.TOKEN_ISSUED,
            principal_id="alice@corp.example.com",
            app_id="app_ms_graph",
            session_id=session,
            token_id=token,
            ip_address="8.8.8.1",
            geo=GeoLocation(country="US", city="Mountain View", asn="AS15169"),
            timestamp=_dt("2026-06-18T10:00:00"),
        ),
        IdentityEvent(
            id="evt_replay_002",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.TOKEN_REFRESH,
            principal_id="alice@corp.example.com",
            app_id="app_ms_graph",
            session_id=session,
            token_id=token,
            ip_address="13.107.4.1",
            geo=GeoLocation(country="US", city="Redmond", asn="AS8075"),
            timestamp=_dt("2026-06-18T10:18:00"),
        ),
    ]


def clean_token_events() -> list[IdentityEvent]:
    """Same session_id from the SAME ASN — no replay signal."""
    session = "session_CLEAN_TOKEN_001"
    return [
        IdentityEvent(
            id="evt_clean_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.TOKEN_ISSUED,
            principal_id="bob@corp.example.com",
            session_id=session,
            token_id="jti_CLEAN_TOKEN_001",
            ip_address="8.8.8.10",
            geo=GeoLocation(country="US", city="Mountain View", asn="AS15169"),
            timestamp=_dt("2026-06-18T11:00:00"),
        ),
        IdentityEvent(
            id="evt_clean_002",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.TOKEN_REFRESH,
            principal_id="bob@corp.example.com",
            session_id=session,
            token_id="jti_CLEAN_TOKEN_001",
            ip_address="8.8.8.11",
            geo=GeoLocation(country="US", city="Mountain View", asn="AS15169"),
            timestamp=_dt("2026-06-18T11:15:00"),
        ),
    ]


# ── Dormant app reactivation ───────────────────────────────────────────────


def dormant_grant_and_events() -> tuple[list[OAuthGrant], list[IdentityEvent]]:
    """OAuthGrant idle 100 days then activity event — should flag."""
    grant = OAuthGrant(
        id="grant_DORMANT_001",
        org_id=_ORG,
        app_id="app_FORGOTTEN_SAAS_001",
        app_display_name="ForgottenSaaS",
        principal_id="alice@corp.example.com",
        provider=IdentityProvider.ENTRA,
        scopes=["Mail.Read", "Calendars.Read"],
        consent_type=OAuthConsentType.USER,
        granted_at=_dt("2025-06-01T09:00:00"),
        # last_used is 100 days before the activity event on 2026-06-18
        last_used=_dt("2026-03-10T09:00:00"),
    )
    event = IdentityEvent(
        id="evt_dormant_reactivation_001",
        org_id=_ORG,
        provider=_PROVIDER,
        kind=IdentityEventKind.TOKEN_ISSUED,
        principal_id="alice@corp.example.com",
        app_id="app_FORGOTTEN_SAAS_001",
        timestamp=_dt("2026-06-18T14:00:00"),
    )
    return [grant], [event]


def active_grant_and_events() -> tuple[list[OAuthGrant], list[IdentityEvent]]:
    """OAuthGrant used 10 days ago — should NOT flag dormant reactivation."""
    grant = OAuthGrant(
        id="grant_ACTIVE_001",
        org_id=_ORG,
        app_id="app_ACTIVE_SAAS_001",
        app_display_name="ActiveSaaS",
        principal_id="charlie@corp.example.com",
        provider=IdentityProvider.ENTRA,
        scopes=["User.Read"],
        consent_type=OAuthConsentType.USER,
        granted_at=_dt("2026-01-01T09:00:00"),
        last_used=_dt("2026-06-08T09:00:00"),  # only 10 days idle
    )
    event = IdentityEvent(
        id="evt_active_app_001",
        org_id=_ORG,
        provider=_PROVIDER,
        kind=IdentityEventKind.TOKEN_ISSUED,
        principal_id="charlie@corp.example.com",
        app_id="app_ACTIVE_SAAS_001",
        timestamp=_dt("2026-06-18T14:00:00"),
    )
    return [grant], [event]


# ── Impossible travel ──────────────────────────────────────────────────────


def impossible_travel_events() -> list[IdentityEvent]:
    """London then New York 5 minutes apart — ~68 000 km/h, should flag."""
    return [
        IdentityEvent(
            id="evt_travel_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.LOGIN_SUCCESS,
            principal_id="diana@corp.example.com",
            ip_address="5.148.0.1",
            geo=GeoLocation(
                country="GB",
                city="London",
                latitude=51.5074,
                longitude=-0.1278,
                asn="AS2856",
            ),
            timestamp=_dt("2026-06-18T08:00:00"),
        ),
        IdentityEvent(
            id="evt_travel_002",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.LOGIN_SUCCESS,
            principal_id="diana@corp.example.com",
            ip_address="23.100.0.1",
            geo=GeoLocation(
                country="US",
                city="New York",
                latitude=40.7128,
                longitude=-74.0060,
                asn="AS8075",
            ),
            timestamp=_dt("2026-06-18T08:05:00"),  # 5 min later, 5,570 km away
        ),
    ]


def possible_travel_events() -> list[IdentityEvent]:
    """London then NY 8 hours apart — ~700 km/h, below the threshold."""
    return [
        IdentityEvent(
            id="evt_possible_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.LOGIN_SUCCESS,
            principal_id="evan@corp.example.com",
            ip_address="5.148.0.2",
            geo=GeoLocation(
                country="GB",
                city="London",
                latitude=51.5074,
                longitude=-0.1278,
            ),
            timestamp=_dt("2026-06-18T07:00:00"),
        ),
        IdentityEvent(
            id="evt_possible_002",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.LOGIN_SUCCESS,
            principal_id="evan@corp.example.com",
            ip_address="23.100.0.2",
            geo=GeoLocation(
                country="US",
                city="New York",
                latitude=40.7128,
                longitude=-74.0060,
            ),
            timestamp=_dt("2026-06-18T15:00:00"),  # 8 hours later
        ),
    ]


# ── Service principal credential addition ─────────────────────────────────


def sp_credential_addition_events() -> list[IdentityEvent]:
    """CREDENTIAL_ADDED with app_id — should trigger SP credential addition."""
    return [
        IdentityEvent(
            id="evt_spcred_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.CREDENTIAL_ADDED,
            principal_id="sp-automation@corp.example.com",
            app_id="app_SP_HIGH_PRIV_001",
            ip_address="203.0.113.50",
            timestamp=_dt("2026-06-18T02:34:00"),
        )
    ]


def non_sp_credential_addition_events() -> list[IdentityEvent]:
    """CREDENTIAL_ADDED with no app_id and no SP marker — should NOT trigger."""
    return [
        IdentityEvent(
            id="evt_nonspcred_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.CREDENTIAL_ADDED,
            principal_id="frank@corp.example.com",  # regular user UPN
            app_id="",  # no app_id
            ip_address="10.0.0.1",
            timestamp=_dt("2026-06-18T09:00:00"),
        )
    ]


# ── Federation trust modification ─────────────────────────────────────────


def federation_trust_modification_events() -> list[IdentityEvent]:
    """FEDERATION_TRUST_MODIFIED event — should always trigger."""
    return [
        IdentityEvent(
            id="evt_fedmod_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.FEDERATION_TRUST_MODIFIED,
            principal_id="greta@corp.example.com",
            ip_address="198.51.100.1",
            timestamp=_dt("2026-06-18T03:17:00"),
            raw={"operation": "Set federation settings on domain", "domain": "corp.example.com"},
        )
    ]


# ── MFA fatigue ───────────────────────────────────────────────────────────


def mfa_fatigue_events() -> list[IdentityEvent]:
    """4 MFA_DENIED then MFA_APPROVED within 8 minutes — should flag."""
    principal = "hector@corp.example.com"
    return [
        IdentityEvent(
            id="evt_mfa_deny_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_DENIED,
            principal_id=principal,
            ip_address="45.33.32.156",
            timestamp=_dt("2026-06-18T06:00:00"),
        ),
        IdentityEvent(
            id="evt_mfa_deny_002",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_DENIED,
            principal_id=principal,
            ip_address="45.33.32.156",
            timestamp=_dt("2026-06-18T06:02:00"),
        ),
        IdentityEvent(
            id="evt_mfa_deny_003",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_DENIED,
            principal_id=principal,
            ip_address="45.33.32.156",
            timestamp=_dt("2026-06-18T06:04:00"),
        ),
        IdentityEvent(
            id="evt_mfa_deny_004",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_DENIED,
            principal_id=principal,
            ip_address="45.33.32.156",
            timestamp=_dt("2026-06-18T06:06:00"),
        ),
        IdentityEvent(
            id="evt_mfa_approve_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_APPROVED,
            principal_id=principal,
            ip_address="45.33.32.156",
            timestamp=_dt("2026-06-18T06:08:00"),
        ),
    ]


def mfa_clean_events() -> list[IdentityEvent]:
    """Only 2 denials before approve — below threshold of 3, should NOT flag."""
    principal = "irene@corp.example.com"
    return [
        IdentityEvent(
            id="evt_mfa_clean_deny_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_DENIED,
            principal_id=principal,
            ip_address="10.0.1.1",
            timestamp=_dt("2026-06-18T07:00:00"),
        ),
        IdentityEvent(
            id="evt_mfa_clean_deny_002",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_DENIED,
            principal_id=principal,
            ip_address="10.0.1.1",
            timestamp=_dt("2026-06-18T07:02:00"),
        ),
        IdentityEvent(
            id="evt_mfa_clean_approve_001",
            org_id=_ORG,
            provider=_PROVIDER,
            kind=IdentityEventKind.MFA_APPROVED,
            principal_id=principal,
            ip_address="10.0.1.1",
            timestamp=_dt("2026-06-18T07:04:00"),
        ),
    ]
