"""Pure-logic identity detectors for the Identity Hunt Agent (Phase 6 #116).

Dependency-free (no DB, no network, no LLM) — operates entirely on
:mod:`btagent_shared.types.identity_hunt` models loaded from fixture data or
from provider events pre-fetched by the live connectors (#100).

The six detectors implemented here are decidable from event data alone:

1. **oauth_token_replay** — same token_id / session_id observed from multiple
   ASNs or geographies within a short window (default: 30 min, 2+ distinct ASNs).
2. **dormant_app_reactivation** — an OAuth grant whose ``last_used`` was >90 days
   ago suddenly generates activity events.
3. **impossible_travel** — two sign-in events for the same principal from
   geo-locations whose physical distance implies an impossible flight time.
4. **service_principal_credential_addition** — a CREDENTIAL_ADDED event for a
   service principal (non-human), especially one that already held a credential.
5. **federation_trust_modification** — any FEDERATION_TRUST_MODIFIED event;
   always high severity (Silver Ticket / Golden SAML precursor).
6. **mfa_fatigue** — N consecutive MFA_DENIED events for the same principal
   followed by an MFA_APPROVED (default: 3 denials in 10 min before approve).

Each detector returns a list of :class:`~btagent_shared.types.identity_hunt.IdentityDetectionResult`
objects. The helper :func:`to_record_finding_request` converts each result into
a :class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` ready for
the #119 triage queue.

Deferred (requires live connector):
- Stale-session enumeration (needs real-time Okta session API).
- Privileged-role assignment outside change window (needs calendar/change-mgmt feed).
- Cross-tenant OAuth token abuse (needs multi-tenant graph join).
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from btagent_shared.types.hunt_finding import (
    HuntDomain,
    HuntEntity,
    HuntObservable,
    HuntSource,
    RecordFindingRequest,
)
from btagent_shared.types.identity_hunt import (
    GeoLocation,
    IdentityDetectionResult,
    IdentityEvent,
    IdentityEventKind,
    OAuthGrant,
)

# ---------------------------------------------------------------------------
# Constants (tunable per-call via kwargs)
# ---------------------------------------------------------------------------

_REPLAY_WINDOW_MINUTES: int = 30
_REPLAY_MIN_ASN_COUNT: int = 2
_DORMANT_IDLE_DAYS: int = 90
_IMPOSSIBLE_TRAVEL_MIN_SPEED_KMH: float = 900.0  # faster than a commercial jet
_MFA_FATIGUE_DENIAL_THRESHOLD: int = 3
_MFA_FATIGUE_WINDOW_MINUTES: int = 10

# MITRE technique IDs per detection (pre-mapped to avoid mapper round-trips)
_TECHNIQUES: dict[str, list[str]] = {
    "oauth_token_replay": ["T1550.001", "T1078"],
    "dormant_app_reactivation": ["T1550.001", "T1078.004"],
    "impossible_travel": ["T1078", "T1078.004"],
    "service_principal_credential_addition": ["T1098.001", "T1098"],
    "federation_trust_modification": ["T1484.002", "T1556"],
    "mfa_fatigue": ["T1621", "T1078"],
}


# ---------------------------------------------------------------------------
# Geo helpers (pure math, no network)
# ---------------------------------------------------------------------------


def _haversine_km(geo_a: GeoLocation, geo_b: GeoLocation) -> float | None:
    """Great-circle distance in km between two GeoLocation objects.

    Returns ``None`` if either location is missing lat/lon.
    """
    if (
        geo_a.latitude is None
        or geo_a.longitude is None
        or geo_b.latitude is None
        or geo_b.longitude is None
    ):
        return None

    r = 6_371.0  # Earth radius in km
    lat1, lon1 = math.radians(geo_a.latitude), math.radians(geo_a.longitude)
    lat2, lon2 = math.radians(geo_b.latitude), math.radians(geo_b.longitude)
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return r * 2 * math.asin(math.sqrt(a))


def _speed_kmh(geo_a: GeoLocation, geo_b: GeoLocation, elapsed: timedelta) -> float | None:
    """Return km/h between two locations over ``elapsed`` time, or ``None``."""
    dist = _haversine_km(geo_a, geo_b)
    if dist is None:
        return None
    hours = elapsed.total_seconds() / 3600
    if hours <= 0:
        return None
    return dist / hours


# ---------------------------------------------------------------------------
# Detector 1 — OAuth token / session replay
# ---------------------------------------------------------------------------


def detect_oauth_token_replay(
    events: list[IdentityEvent],
    *,
    window_minutes: int = _REPLAY_WINDOW_MINUTES,
    min_asn_count: int = _REPLAY_MIN_ASN_COUNT,
) -> list[IdentityDetectionResult]:
    """Flag session or token IDs observed from multiple ASNs in a short window.

    Groups events by (principal_id, token_id or session_id) and checks whether
    the same credential materialises from ``min_asn_count`` or more distinct ASNs
    within ``window_minutes``.

    Parameters
    ----------
    events:
        Raw identity events (filtered to TOKEN_ISSUED / TOKEN_REFRESH preferred,
        but any event with a non-empty session_id or token_id is evaluated).
    window_minutes:
        Rolling time window in which ASN diversity is measured.
    min_asn_count:
        Minimum number of distinct ASNs to trigger.

    Returns
    -------
    list[IdentityDetectionResult]
        One result per flagged (principal, credential) pair.
    """
    # key: (principal_id, cred_type, cred_key) -> list[(timestamp, asn, ip, event_id)]
    # Emit one observation per *populated* credential identifier so that a stolen
    # session reused with refreshed (different) access-token IDs across ASNs is
    # still caught on the session dimension, and vice-versa.
    cred_observations: dict[tuple[str, str, str], list[tuple[datetime, str, str, str]]] = (
        defaultdict(list)
    )

    for evt in events:
        asn_or_ip = evt.geo.asn or evt.ip_address
        obs_entry = (evt.timestamp, asn_or_ip, evt.ip_address, evt.id)
        if evt.token_id:
            cred_observations[(evt.principal_id, "token", evt.token_id)].append(obs_entry)
        if evt.session_id:
            cred_observations[(evt.principal_id, "session", evt.session_id)].append(obs_entry)
        if not evt.token_id and not evt.session_id:
            continue

    results: list[IdentityDetectionResult] = []
    window = timedelta(minutes=window_minutes)

    for (principal_id, cred_type, cred_key), obs in cred_observations.items():
        # Sort by time and slide the window
        obs_sorted = sorted(obs, key=lambda x: x[0])
        for i, (ts_anchor, _, _, _) in enumerate(obs_sorted):
            window_obs = [o for o in obs_sorted[i:] if o[0] - ts_anchor <= window]
            asns = {o[1] for o in window_obs if o[1]}
            if len(asns) >= min_asn_count:
                event_ids = [o[3] for o in window_obs]
                results.append(
                    IdentityDetectionResult(
                        detection_id=f"idr-replay-{principal_id}-{cred_type}-{cred_key[:16]}-{i}",
                        rule_id="identity.oauth_token_replay",
                        title=f"OAuth token/session replay: {principal_id}",
                        description=(
                            f"{cred_type.title()} '{cred_key[:24]}…' for principal "
                            f"'{principal_id}' was observed from {len(asns)} distinct ASNs "
                            f"({', '.join(sorted(asns))}) within a {window_minutes}-minute window. "
                            "This pattern is consistent with stolen-token replay across "
                            "geographically dispersed infrastructure (T1550.001)."
                        ),
                        severity="high",
                        confidence=min(0.95, 0.6 + 0.1 * (len(asns) - min_asn_count)),
                        technique_ids=_TECHNIQUES["oauth_token_replay"],
                        entity_kind="user",
                        entity_value=principal_id,
                        observable_type=f"{cred_type}_id",
                        observable_value=cred_key[:256],
                        evidence={
                            "cred_type": cred_type,
                            "cred_key": cred_key[:64],
                            "distinct_asns": sorted(asns),
                            "window_minutes": window_minutes,
                            "event_ids": event_ids,
                            "anchor_ts": ts_anchor.isoformat(),
                        },
                    )
                )
                break  # one result per (principal, cred_type, cred) pair

    return results


# ---------------------------------------------------------------------------
# Detector 2 — Dormant app reactivation
# ---------------------------------------------------------------------------


def detect_dormant_app_reactivation(
    grants: list[OAuthGrant],
    events: list[IdentityEvent],
    *,
    idle_days: int = _DORMANT_IDLE_DAYS,
) -> list[IdentityDetectionResult]:
    """Flag OAuth apps that were idle >``idle_days`` and are now generating activity.

    Parameters
    ----------
    grants:
        All known OAuth grants for the org. A grant is "dormant" when its
        ``last_used`` is more than ``idle_days`` before the earliest activity
        event in ``events``.
    events:
        Recent activity events (from the scan window). App IDs present here
        that map to dormant grants are flagged.
    idle_days:
        Idle threshold in days (default 90, per the issue spec).
    """
    if not events:
        return []

    earliest_event = min(evt.timestamp for evt in events)
    idle_threshold = timedelta(days=idle_days)

    # Build dormant grant index: (principal_id, app_id) -> grant
    # Keying by (principal_id, app_id) prevents Alice's dormant grant from being
    # emitted on Bob's event, and avoids multiple dormant grants overwriting each
    # other when several principals share the same app.
    dormant: dict[tuple[str, str], OAuthGrant] = {}
    for grant in grants:
        if grant.revoked_at is not None:
            continue  # already revoked; not a reactivation
        if grant.last_used is None:
            # Never used since grant — dormant from grant_date perspective
            if earliest_event - grant.granted_at >= idle_threshold:
                dormant[(grant.principal_id, grant.app_id)] = grant
        else:
            if earliest_event - grant.last_used >= idle_threshold:
                dormant[(grant.principal_id, grant.app_id)] = grant

    results: list[IdentityDetectionResult] = []
    seen_keys: set[tuple[str, str]] = set()

    for evt in events:
        if not evt.app_id:
            continue
        key = (evt.principal_id, evt.app_id)
        if key not in dormant:
            continue
        if key in seen_keys:
            continue
        seen_keys.add(key)

        grant = dormant[key]
        idle_since = grant.last_used or grant.granted_at
        idle_duration_days = (earliest_event - idle_since).days

        results.append(
            IdentityDetectionResult(
                detection_id=f"idr-dormant-{grant.app_id[:32]}-{grant.principal_id[:16]}",
                rule_id="identity.dormant_app_reactivation",
                title=f"Dormant OAuth app reactivated: {grant.app_display_name or grant.app_id}",
                description=(
                    f"OAuth app '{grant.app_display_name or grant.app_id}' (app_id={grant.app_id}) "
                    f"has been idle for {idle_duration_days} days (threshold: {idle_days}d) "
                    f"but generated activity on {evt.timestamp.date().isoformat()}. "
                    "Dormant app reactivation may indicate a compromised or forgotten third-party "
                    "app OAuth grant being exploited (T1550.001, T1078.004)."
                ),
                severity="high",
                confidence=0.8,
                technique_ids=_TECHNIQUES["dormant_app_reactivation"],
                entity_kind="oauth_app",
                entity_value=grant.app_id,
                observable_type="oauth_app_id",
                observable_value=grant.app_id,
                evidence={
                    "app_id": grant.app_id,
                    "app_display_name": grant.app_display_name,
                    "principal_id": grant.principal_id,
                    "idle_days": idle_duration_days,
                    "last_used": idle_since.isoformat(),
                    "reactivation_event_id": evt.id,
                    "reactivation_ts": evt.timestamp.isoformat(),
                    "scopes": grant.scopes,
                    "consent_type": grant.consent_type,
                },
            )
        )

    return results


# ---------------------------------------------------------------------------
# Detector 3 — Impossible travel
# ---------------------------------------------------------------------------


def detect_impossible_travel(
    events: list[IdentityEvent],
    *,
    min_speed_kmh: float = _IMPOSSIBLE_TRAVEL_MIN_SPEED_KMH,
) -> list[IdentityDetectionResult]:
    """Flag sign-in pairs for the same principal that imply impossible travel.

    Considers only events with lat/lon populated (requires IP-to-geo enrichment
    from the connector layer, or pre-enriched fixture events). The speed threshold
    defaults to 900 km/h (faster than a commercial jet).

    Parameters
    ----------
    events:
        All identity events; non-login events are filtered out internally.
    min_speed_kmh:
        Minimum speed (km/h) to consider the travel impossible.
    """
    # Filter to sign-in events with usable geo
    login_events = [
        evt
        for evt in events
        if evt.kind in {IdentityEventKind.LOGIN_SUCCESS, IdentityEventKind.TOKEN_ISSUED}
        and evt.geo.latitude is not None
        and evt.geo.longitude is not None
    ]

    # Group by principal
    by_principal: dict[str, list[IdentityEvent]] = defaultdict(list)
    for evt in login_events:
        by_principal[evt.principal_id].append(evt)

    results: list[IdentityDetectionResult] = []

    for principal_id, evts in by_principal.items():
        evts_sorted = sorted(evts, key=lambda e: e.timestamp)
        for i in range(len(evts_sorted) - 1):
            a = evts_sorted[i]
            b = evts_sorted[i + 1]
            elapsed = b.timestamp - a.timestamp
            speed = _speed_kmh(a.geo, b.geo, elapsed)
            if speed is None:
                continue
            if speed < min_speed_kmh:
                continue

            dist = _haversine_km(a.geo, b.geo) or 0.0
            results.append(
                IdentityDetectionResult(
                    detection_id=f"idr-travel-{principal_id[:24]}-{a.id[:12]}-{b.id[:12]}",
                    rule_id="identity.impossible_travel",
                    title=f"Impossible travel detected: {principal_id}",
                    description=(
                        f"Principal '{principal_id}' signed in from "
                        f"{a.geo.city or a.geo.country or a.ip_address} "
                        f"at {a.timestamp.isoformat()} then "
                        f"{b.geo.city or b.geo.country or b.ip_address} "
                        f"at {b.timestamp.isoformat()} — "
                        f"{dist:.0f} km in {elapsed.total_seconds() / 60:.1f} min "
                        f"({speed:.0f} km/h, threshold {min_speed_kmh:.0f} km/h). "
                        "This pattern indicates simultaneous sessions from different "
                        "locations and is a strong indicator of account compromise (T1078)."
                    ),
                    severity="high",
                    confidence=0.9,
                    technique_ids=_TECHNIQUES["impossible_travel"],
                    entity_kind="user",
                    entity_value=principal_id,
                    observable_type="ip",
                    observable_value=b.ip_address or b.geo.country,
                    evidence={
                        "event_a_id": a.id,
                        "event_b_id": b.id,
                        "location_a": {
                            "country": a.geo.country,
                            "city": a.geo.city,
                            "ip": a.ip_address,
                            "ts": a.timestamp.isoformat(),
                        },
                        "location_b": {
                            "country": b.geo.country,
                            "city": b.geo.city,
                            "ip": b.ip_address,
                            "ts": b.timestamp.isoformat(),
                        },
                        "distance_km": round(dist, 1),
                        "elapsed_minutes": round(elapsed.total_seconds() / 60, 1),
                        "speed_kmh": round(speed, 1),
                    },
                )
            )

    return results


# ---------------------------------------------------------------------------
# Detector 4 — Service principal credential addition
# ---------------------------------------------------------------------------


def detect_service_principal_credential_addition(
    events: list[IdentityEvent],
) -> list[IdentityDetectionResult]:
    """Flag CREDENTIAL_ADDED events targeting service principals.

    Service principal credential additions are a common persistence / privilege
    escalation technique (T1098.001): adding a new client secret or certificate
    to a high-privilege service principal allows an attacker to authenticate as
    that principal without MFA.

    All CREDENTIAL_ADDED events where the target looks like a service principal
    (heuristic: app_id present and principal_id matches a service-account pattern)
    are flagged.
    """
    results: list[IdentityDetectionResult] = []

    for evt in events:
        if evt.kind != IdentityEventKind.CREDENTIAL_ADDED:
            continue
        # Flag if app_id is non-empty (service principal credential context)
        # or if principal_id contains common SP patterns
        is_sp = bool(evt.app_id) or any(
            marker in evt.principal_id.lower()
            for marker in ("sp-", "svc-", "service-", "principal-", "@app")
        )
        if not is_sp:
            continue

        results.append(
            IdentityDetectionResult(
                detection_id=f"idr-spcred-{evt.principal_id[:32]}-{evt.id[:12]}",
                rule_id="identity.service_principal_credential_addition",
                title=f"Service principal credential addition: {evt.principal_id}",
                description=(
                    f"A new credential was added to service principal '{evt.principal_id}' "
                    f"(app_id={evt.app_id or 'unknown'}) at {evt.timestamp.isoformat()}. "
                    "Attackers add rogue credentials to high-privilege service principals "
                    "to establish persistent backdoor access without MFA (T1098.001)."
                ),
                severity="high",
                confidence=0.85,
                technique_ids=_TECHNIQUES["service_principal_credential_addition"],
                entity_kind="service_principal",
                entity_value=evt.principal_id,
                observable_type="app_id",
                observable_value=evt.app_id or evt.principal_id,
                evidence={
                    "event_id": evt.id,
                    "principal_id": evt.principal_id,
                    "app_id": evt.app_id,
                    "provider": evt.provider,
                    "ip_address": evt.ip_address,
                    "ts": evt.timestamp.isoformat(),
                },
            )
        )

    return results


# ---------------------------------------------------------------------------
# Detector 5 — Federation trust modification
# ---------------------------------------------------------------------------


def detect_federation_trust_modification(
    events: list[IdentityEvent],
) -> list[IdentityDetectionResult]:
    """Flag any FEDERATION_TRUST_MODIFIED event.

    Federation trust modifications are always high severity: modifying a SAML
    federation trust can enable a Golden SAML attack (T1484.002) where an
    attacker can generate valid authentication assertions for any user without
    knowing their password.

    Every such event is flagged regardless of who made the change — the change
    itself is the anomaly (any modification should be on a CAB record).
    """
    results: list[IdentityDetectionResult] = []

    for evt in events:
        if evt.kind != IdentityEventKind.FEDERATION_TRUST_MODIFIED:
            continue

        results.append(
            IdentityDetectionResult(
                detection_id=f"idr-fedmod-{evt.principal_id[:32]}-{evt.id[:12]}",
                rule_id="identity.federation_trust_modification",
                title=f"Federation trust modified by: {evt.principal_id}",
                description=(
                    f"A federation trust was modified by '{evt.principal_id}' "
                    f"at {evt.timestamp.isoformat()} (provider: {evt.provider}). "
                    "This is a critical action: modifying a SAML identity provider trust "
                    "can enable Golden SAML attacks where an adversary forges authentication "
                    "assertions for any user in the tenant (T1484.002 / T1556)."
                ),
                severity="critical",
                confidence=0.95,
                technique_ids=_TECHNIQUES["federation_trust_modification"],
                entity_kind="user",
                entity_value=evt.principal_id,
                observable_type="ip",
                observable_value=evt.ip_address or "unknown",
                evidence={
                    "event_id": evt.id,
                    "principal_id": evt.principal_id,
                    "provider": evt.provider,
                    "ip_address": evt.ip_address,
                    "ts": evt.timestamp.isoformat(),
                    "raw": evt.raw,
                },
            )
        )

    return results


# ---------------------------------------------------------------------------
# Detector 6 — MFA fatigue
# ---------------------------------------------------------------------------


def detect_mfa_fatigue(
    events: list[IdentityEvent],
    *,
    denial_threshold: int = _MFA_FATIGUE_DENIAL_THRESHOLD,
    window_minutes: int = _MFA_FATIGUE_WINDOW_MINUTES,
) -> list[IdentityDetectionResult]:
    """Flag MFA fatigue attacks: N denials followed by an approval in a short window.

    MFA fatigue (aka MFA bombing / push spam) is a social engineering technique
    where an attacker with valid credentials sends repeated MFA push notifications
    until the user approves one (T1621). The attacker typically has the correct
    password (acquired via phishing or credential stuffing) so authentication
    succeeds as soon as the user tires of dismissing the pushes.

    Parameters
    ----------
    events:
        All identity events. MFA_DENIED / MFA_APPROVED events are extracted.
    denial_threshold:
        Minimum number of denials before an approval to trigger (default 3).
    window_minutes:
        Window in which the denial run must occur before the approval.
    """
    # Group MFA events by principal
    mfa_events: dict[str, list[IdentityEvent]] = defaultdict(list)
    for evt in events:
        if evt.kind in {
            IdentityEventKind.MFA_DENIED,
            IdentityEventKind.MFA_APPROVED,
            IdentityEventKind.MFA_CHALLENGE,
        }:
            mfa_events[evt.principal_id].append(evt)

    results: list[IdentityDetectionResult] = []
    window = timedelta(minutes=window_minutes)

    for principal_id, mfa_evts in mfa_events.items():
        sorted_evts = sorted(mfa_evts, key=lambda e: e.timestamp)

        for i, evt in enumerate(sorted_evts):
            if evt.kind != IdentityEventKind.MFA_APPROVED:
                continue

            # Find the previous approval (if any) to bound the denial run.
            # Denials that occurred before an earlier approval belong to a
            # previous (resolved) authentication attempt and must not be
            # counted toward the current run — otherwise an interrupted denial
            # sequence followed by a legitimate approval wrongly re-fires.
            prev_approvals = [
                e for e in sorted_evts[:i] if e.kind == IdentityEventKind.MFA_APPROVED
            ]
            run_start = prev_approvals[-1].timestamp if prev_approvals else None

            # Look backward in the window for denials *after* the previous approval
            denials = [
                e
                for e in sorted_evts[:i]
                if e.kind == IdentityEventKind.MFA_DENIED
                and evt.timestamp - e.timestamp <= window
                and (run_start is None or e.timestamp > run_start)
            ]

            if len(denials) < denial_threshold:
                continue

            denial_event_ids = [d.id for d in denials]
            results.append(
                IdentityDetectionResult(
                    detection_id=f"idr-mfafatigue-{principal_id[:32]}-{evt.id[:12]}",
                    rule_id="identity.mfa_fatigue",
                    title=f"MFA fatigue attack: {principal_id}",
                    description=(
                        f"Principal '{principal_id}' received {len(denials)} MFA denial(s) "
                        f"within {window_minutes} minutes before approving at "
                        f"{evt.timestamp.isoformat()}. "
                        "This pattern is consistent with an MFA fatigue / push-bombing attack "
                        "where an adversary with valid credentials repeatedly requests MFA "
                        "push notifications until the user approves one (T1621)."
                    ),
                    severity="high",
                    confidence=min(0.95, 0.65 + 0.05 * len(denials)),
                    technique_ids=_TECHNIQUES["mfa_fatigue"],
                    entity_kind="user",
                    entity_value=principal_id,
                    observable_type="ip",
                    observable_value=evt.ip_address or "unknown",
                    evidence={
                        "approval_event_id": evt.id,
                        "approval_ts": evt.timestamp.isoformat(),
                        "denial_count": len(denials),
                        "denial_event_ids": denial_event_ids,
                        "window_minutes": window_minutes,
                        "ip_address": evt.ip_address,
                    },
                )
            )

    return results


# ---------------------------------------------------------------------------
# Convenience: run all detectors on a unified event set
# ---------------------------------------------------------------------------


def run_all_detectors(
    events: list[IdentityEvent],
    grants: list[OAuthGrant] | None = None,
    *,
    replay_window_minutes: int = _REPLAY_WINDOW_MINUTES,
    replay_min_asn_count: int = _REPLAY_MIN_ASN_COUNT,
    dormant_idle_days: int = _DORMANT_IDLE_DAYS,
    impossible_travel_min_speed_kmh: float = _IMPOSSIBLE_TRAVEL_MIN_SPEED_KMH,
    mfa_fatigue_denial_threshold: int = _MFA_FATIGUE_DENIAL_THRESHOLD,
    mfa_fatigue_window_minutes: int = _MFA_FATIGUE_WINDOW_MINUTES,
) -> list[IdentityDetectionResult]:
    """Run all six identity detectors and return the union of results.

    Convenience wrapper used by the hunt-pack runner and golden tests.
    Each detector is independent and failures in one do not suppress others.

    Parameters
    ----------
    events:
        Combined identity event stream for the hunt window.
    grants:
        Optional OAuth grant snapshot. Required for dormant-app detection;
        other detectors operate on events alone. Pass ``[]`` if unavailable.

    Returns
    -------
    list[IdentityDetectionResult]
        Deduplicated (by detection_id) results from all detectors.
    """
    all_results: list[IdentityDetectionResult] = []
    seen_ids: set[str] = set()

    def _extend(new: list[IdentityDetectionResult]) -> None:
        for r in new:
            if r.detection_id not in seen_ids:
                seen_ids.add(r.detection_id)
                all_results.append(r)

    _extend(
        detect_oauth_token_replay(
            events,
            window_minutes=replay_window_minutes,
            min_asn_count=replay_min_asn_count,
        )
    )
    _extend(
        detect_dormant_app_reactivation(
            grants or [],
            events,
            idle_days=dormant_idle_days,
        )
    )
    _extend(detect_impossible_travel(events, min_speed_kmh=impossible_travel_min_speed_kmh))
    _extend(detect_service_principal_credential_addition(events))
    _extend(detect_federation_trust_modification(events))
    _extend(
        detect_mfa_fatigue(
            events,
            denial_threshold=mfa_fatigue_denial_threshold,
            window_minutes=mfa_fatigue_window_minutes,
        )
    )

    return all_results


# ---------------------------------------------------------------------------
# Emit: convert results → RecordFindingRequest
# ---------------------------------------------------------------------------


def to_record_finding_request(result: IdentityDetectionResult) -> RecordFindingRequest:
    """Convert an :class:`IdentityDetectionResult` to a :class:`RecordFindingRequest`.

    This is the bridge from the pure-logic detector output to the #119
    HuntFinding queue. The source and domain are always ``identity``.
    """
    entities: list[HuntEntity] = []
    if result.entity_value:
        entities.append(HuntEntity(kind=result.entity_kind, value=result.entity_value))

    observables: list[HuntObservable] = []
    if result.observable_value and result.observable_type:
        observables.append(
            HuntObservable(type=result.observable_type, value=result.observable_value)
        )

    return RecordFindingRequest(
        source=HuntSource.IDENTITY,
        domain=HuntDomain.IDENTITY,
        title=result.title,
        description=result.description,
        severity=result.severity,  # type: ignore[arg-type]
        confidence=result.confidence,
        technique_ids=result.technique_ids,
        entities=entities,
        observables=observables,
        evidence={
            "rule_id": result.rule_id,
            "detection_id": result.detection_id,
            **result.evidence,
        },
    )


def results_to_findings(
    results: list[IdentityDetectionResult],
) -> list[RecordFindingRequest]:
    """Batch-convert detection results to RecordFindingRequest payloads."""
    return [to_record_finding_request(r) for r in results]


# ---------------------------------------------------------------------------
# OAuth grant graph builder (pure data structure, no network)
# ---------------------------------------------------------------------------


def build_grant_graph(
    grants: list[OAuthGrant],
) -> dict[str, Any]:
    """Build an in-memory principal↔app↔scope grant graph from a grant list.

    Returns a nested dict for display / traversal::

        {principal_id: {app_id: [{"grant_id": ..., "scopes": [...], ...}, ...]}}

    A provider can issue multiple grants for the same (principal, app) pair —
    for example, resource-specific scope bundles or tenant-scoped consents.
    Keying by a single dict value per (principal, app) silently drops earlier
    grants and loses scope coverage for over-privilege analysis. The graph
    therefore retains a *list* of grant entries so no grant is discarded.

    Used by the hunt-pack runner to enumerate over-privileged grants.
    """
    graph: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for grant in grants:
        if grant.revoked_at is not None:
            continue
        graph[grant.principal_id][grant.app_id].append(
            {
                "grant_id": grant.id,
                "scopes": list(grant.scopes),
                "consent_type": grant.consent_type,
                "granted_at": grant.granted_at.isoformat(),
                "last_used": grant.last_used.isoformat() if grant.last_used else None,
                "app_display_name": grant.app_display_name,
                "provider": grant.provider,
            }
        )
    # Convert inner defaultdicts to plain dicts for a clean return type
    return {pid: dict(apps) for pid, apps in graph.items()}
