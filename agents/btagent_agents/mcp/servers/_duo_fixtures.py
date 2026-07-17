"""Recorded Cisco Duo Admin API fixtures for mock-mode responses (#100 Tier-2).

Shapes mirror the Duo Admin API surfaces the live connector will call:

- ``DUO_FIXTURE_AUTH_LOGS`` — ``/admin/v2/logs/authentication`` rows
  (``result`` success/denied/fraud, ``factor``, ``reason``, ``user``,
  ``access_device`` with ip + location).
- ``DUO_FIXTURE_USERS`` — ``/admin/v1/users`` records (status, phones,
  bypass-code count, last login).
- ``DUO_FIXTURE_ADMIN_LOGS`` — ``/admin/v1/logs/administrator`` rows (admin
  panel actions: user create, bypass-code create, policy change).

The fixtures tell one coherent MFA-fatigue → fraudulent-approval →
persistence story for ``dkim@example.com``:

* A burst of ``duo_push`` prompts from an unfamiliar IP (198.51.100.77,
  "Reykjavik, IS" — a location the user never signs in from): four
  ``denied`` (reason ``user_marked_fraud`` / ``no_response``) then one
  ``fraud``-flagged success (the user caved).
* An admin then generates a **bypass code** for dkim (persistence that
  sidesteps MFA entirely) and creates a new admin ``svc-break-glass``.
* ``bwallace@example.com`` is the quiet comparison user (one clean push
  success from the corporate range).

Join discipline: ``user.name`` (primary email) is the principal on every
surface; ``access_device.ip`` carries the attacker infrastructure.
"""

from __future__ import annotations

from typing import Any

ATTACKER_IP = "198.51.100.77"

DUO_FIXTURE_AUTH_LOGS: list[dict[str, Any]] = [
    # --- MFA-fatigue burst against dkim from the attacker IP ---
    {
        "timestamp": "2026-06-28T09:00:05Z",
        "result": "denied",
        "reason": "user_marked_fraud",
        "factor": "duo_push",
        "user": {"name": "dkim@example.com", "key": "DU111111111111111111"},
        "application": {"name": "VPN Gateway"},
        "access_device": {"ip": ATTACKER_IP, "location": {"city": "Reykjavik", "country": "IS"}},
    },
    {
        "timestamp": "2026-06-28T09:00:41Z",
        "result": "denied",
        "reason": "no_response",
        "factor": "duo_push",
        "user": {"name": "dkim@example.com", "key": "DU111111111111111111"},
        "application": {"name": "VPN Gateway"},
        "access_device": {"ip": ATTACKER_IP, "location": {"city": "Reykjavik", "country": "IS"}},
    },
    {
        "timestamp": "2026-06-28T09:01:20Z",
        "result": "denied",
        "reason": "no_response",
        "factor": "duo_push",
        "user": {"name": "dkim@example.com", "key": "DU111111111111111111"},
        "application": {"name": "VPN Gateway"},
        "access_device": {"ip": ATTACKER_IP, "location": {"city": "Reykjavik", "country": "IS"}},
    },
    {
        "timestamp": "2026-06-28T09:02:11Z",
        "result": "denied",
        "reason": "no_response",
        "factor": "duo_push",
        "user": {"name": "dkim@example.com", "key": "DU111111111111111111"},
        "application": {"name": "VPN Gateway"},
        "access_device": {"ip": ATTACKER_IP, "location": {"city": "Reykjavik", "country": "IS"}},
    },
    {
        "timestamp": "2026-06-28T09:03:02Z",
        "result": "fraud",
        "reason": "user_approved",
        "factor": "duo_push",
        "user": {"name": "dkim@example.com", "key": "DU111111111111111111"},
        "application": {"name": "VPN Gateway"},
        "access_device": {"ip": ATTACKER_IP, "location": {"city": "Reykjavik", "country": "IS"}},
    },
    # --- clean comparison login ---
    {
        "timestamp": "2026-06-28T13:15:00Z",
        "result": "success",
        "reason": "valid_passcode",
        "factor": "passcode",
        "user": {"name": "bwallace@example.com", "key": "DU222222222222222222"},
        "application": {"name": "Web SSO"},
        "access_device": {"ip": "203.0.113.20", "location": {"city": "Austin", "country": "US"}},
    },
]


DUO_FIXTURE_USERS: list[dict[str, Any]] = [
    {
        "user_id": "DU111111111111111111",
        "username": "dkim@example.com",
        "realname": "Dana Kim",
        "status": "active",
        "is_enrolled": True,
        "last_login": "2026-06-28T09:03:02Z",
        "phones": [{"phone_id": "DP1", "number": "+15125550111", "type": "mobile"}],
        "bypass_codes_count": 1,
    },
    {
        "user_id": "DU222222222222222222",
        "username": "bwallace@example.com",
        "realname": "Bea Wallace",
        "status": "active",
        "is_enrolled": True,
        "last_login": "2026-06-28T13:15:00Z",
        "phones": [{"phone_id": "DP2", "number": "+15125550222", "type": "mobile"}],
        "bypass_codes_count": 0,
    },
]


DUO_FIXTURE_ADMIN_LOGS: list[dict[str, Any]] = [
    # Bypass code generated for the compromised user — MFA sidestep persistence.
    {
        "timestamp": "2026-06-28T09:10:00Z",
        "action": "bypass_create",
        "username": "admin@example.com",
        "object": "dkim@example.com",
        "description": "Generated 1 bypass code for user dkim@example.com",
    },
    # New admin account created (break-glass persistence).
    {
        "timestamp": "2026-06-28T09:12:30Z",
        "action": "admin_create",
        "username": "admin@example.com",
        "object": "svc-break-glass@example.com",
        "description": "Created administrator svc-break-glass@example.com (role: Owner)",
    },
    # Routine policy tweak (noise floor).
    {
        "timestamp": "2026-06-27T16:00:00Z",
        "action": "policy_update",
        "username": "secops@example.com",
        "object": "Global Policy",
        "description": "Updated new-user policy: require enrollment",
    },
]
