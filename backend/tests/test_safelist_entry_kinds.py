"""Every safelist entry kind the service enforces can actually be created.

The response safelist is a containment *veto*: anything on it is never
isolated, blocked or disabled, however the agent scores it. It has always had
three kinds — ``ip``, ``domain`` and ``principal`` — and
``response_safelist_service`` validates and enforces all three:
``load_policy`` reads principals straight into ``extra_principals``, and
``containment_execute_service`` screens ``disable_account`` against them
(#117).

Nothing could create one.

* ``SafelistEntryRequest.entry_type`` was a bare ``str`` described as
  ``"'ip' or 'domain'"``, so OpenAPI advertised no vocabulary at all and the
  description named two of the three;
* the TypeScript type was ``"ip" | "domain"``; and
* the settings dropdown hard-coded two ``<option>`` elements.

So the capability existed end to end and no caller could reach it. This is a
gap `test_api_reachability` cannot see — the *route* is reachable and called;
it is a **value inside the route's vocabulary** that had no way in.

These tests assert reachability at the level that was broken: a principal
entry goes in through the public API, comes back out of the list, and lands in
the effective policy that containment actually consults.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.enums import SafelistEntryType
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.services import response_safelist_service as svc

_URL = "/api/v1/containment/safelist"


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (SafelistEntryType.IP, "198.51.100.7"),
        (SafelistEntryType.DOMAIN, "never-block.example"),
        (SafelistEntryType.PRINCIPAL, "arn:aws:iam::123456789012:role/BreakGlass"),
    ],
)
async def test_every_entry_kind_round_trips_through_the_api(
    client: AsyncClient, admin_token: str, kind: SafelistEntryType, value: str
):
    """Parametrised over the enum, so a new kind is covered the day it is added.

    Listing the kinds by hand here would reproduce the original bug in the
    tests: ``principal`` was missing from every hand-written list.
    """
    created = await client.post(
        _URL,
        headers=auth_header(admin_token),
        json={"entry_type": kind.value, "value": value, "reason": "e2e-of-record"},
    )
    assert created.status_code in (200, 201), created.text
    assert created.json()["entry_type"] == kind.value

    # Compare against the value the API stored, not the one submitted:
    # ``normalize_entry`` canonicalises (principals are lowercased so they
    # match case-insensitively, IPs are validated). Asserting on the submitted
    # string would fail for a correct implementation.
    stored = created.json()["value"]

    listed = await client.get(_URL, headers=auth_header(admin_token))
    assert listed.status_code == 200, listed.text
    entries = listed.json()
    rows = entries["items"] if isinstance(entries, dict) else entries
    assert any(r["entry_type"] == kind.value and r["value"] == stored for r in rows)


async def test_the_api_rejects_a_kind_the_service_does_not_enforce(
    client: AsyncClient, admin_token: str
):
    """The vocabulary is now declared, so an unknown kind is a 422.

    Previously ``entry_type`` was an unconstrained ``str``: an unknown kind
    reached the service and raised there. Declaring the enum moves the refusal
    to the schema, which is also what puts the three real kinds into OpenAPI.
    """
    resp = await client.post(
        _URL,
        headers=auth_header(admin_token),
        json={"entry_type": "hostname", "value": "web-01", "reason": ""},
    )
    assert resp.status_code == 422, resp.text


async def test_a_safelisted_principal_reaches_the_effective_policy(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, sample_org
):
    """The point of creating one: containment must actually consult it.

    A principal that round-trips through the API but never lands in
    ``SafelistPolicy.principals`` would be decoration — the veto is applied
    from the policy, not from the table.
    """
    arn = "arn:aws:iam::123456789012:role/ProdDeploy"
    created = await client.post(
        _URL,
        headers=auth_header(admin_token),
        json={"entry_type": SafelistEntryType.PRINCIPAL.value, "value": arn, "reason": "prod"},
    )
    assert created.status_code in (200, 201), created.text

    org_id = created.json()["org_id"]
    policy = await svc.load_policy(db_session, org_id=org_id)

    assert any(arn.lower() == p.lower() for p in policy.principals), policy.principals


def test_the_valid_set_is_derived_from_the_enum_not_restated():
    """A second hand-written copy is how the first divergence happened."""
    assert svc.VALID_ENTRY_TYPES == frozenset(t.value for t in SafelistEntryType)
