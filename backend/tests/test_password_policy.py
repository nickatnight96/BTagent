"""Password policy on registration, and the bcrypt byte ceiling underneath it.

Both of these were found by wiring a UI onto ``POST /auth/register`` — the
last unreached auth route — and they are the reason the slice grew a backend
half:

1. **There was no policy at all.** ``password: str`` carried no constraints,
   so ``{"password": "a"}`` was accepted with a 201. A product with MFA, SAML,
   RBAC and session revocation was issuing one-character credentials.

2. **Over-length passwords were a 500.** bcrypt hashes at most 72 *bytes* and
   bcrypt >= 4.1 raises rather than truncating. Nothing caught that, so a long
   passphrase produced an unhandled ``ValueError``. The serious half is that
   ``verify_password`` sits on the **unauthenticated** login path: any
   anonymous caller could 500 ``POST /auth/login`` by sending 73 bytes.

The rule that must not be "simplified" later: an over-length candidate is
rejected, never truncated to 72 bytes and compared. Truncating would let a
long password authenticate by its prefix — the exact vulnerability the byte
limit causes in older bcrypt versions.
"""

import itertools

import pytest
from helpers import auth_header
from httpx import AsyncClient

from btagent_backend.auth.jwt import (
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_LENGTH,
    hash_password,
    verify_password,
)
from btagent_backend.db.models import UserRow

_n = itertools.count(1)

GOOD_PASSWORD = "Correct-Horse-Battery-9"


def _body(password: str, role: str = "analyst") -> dict:
    i = next(_n)
    return {
        "username": f"pwpolicy_{i}",
        "email": f"pwpolicy_{i}@btagent.test",
        "password": password,
        "role": role,
    }


# ---- The primitives ----


def test_verify_rejects_over_length_instead_of_raising():
    """The unauthenticated-500 fix, at the level it actually lives."""
    stored = hash_password(GOOD_PASSWORD)
    assert verify_password("A" * (MAX_PASSWORD_BYTES + 1), stored) is False


def test_verify_does_not_authenticate_by_truncated_prefix():
    """A long password must not pass by its first 72 bytes.

    If this ever fails, someone has "fixed" the over-length case by truncating
    — which reintroduces the classic bcrypt prefix-collision bug.
    """
    prefix = "P" * MAX_PASSWORD_BYTES
    stored = hash_password(prefix)
    assert verify_password(prefix, stored) is True
    assert verify_password(prefix + "extra", stored) is False


def test_byte_limit_is_measured_in_bytes_not_characters():
    """Non-ASCII counts for more than one — 40 emoji exceed 72 bytes."""
    multibyte = "🔐" * 40
    assert len(multibyte) < MAX_PASSWORD_BYTES
    assert len(multibyte.encode("utf-8")) > MAX_PASSWORD_BYTES
    with pytest.raises(ValueError):
        hash_password(multibyte)


def test_hash_still_works_at_the_boundary():
    exact = "B" * MAX_PASSWORD_BYTES
    assert verify_password(exact, hash_password(exact)) is True


# ---- The endpoint ----


@pytest.mark.asyncio
async def test_register_rejects_a_short_password(client: AsyncClient, admin_token: str):
    """The one-character-password case that used to return 201."""
    resp = await client.post(
        "/api/v1/auth/register", headers=auth_header(admin_token), json=_body("a")
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_rejects_just_below_the_minimum(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(admin_token),
        json=_body("x" * (MIN_PASSWORD_LENGTH - 1)),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_accepts_exactly_the_minimum(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(admin_token),
        json=_body("y" * MIN_PASSWORD_LENGTH),
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_register_rejects_over_length_with_422_not_500(client: AsyncClient, admin_token: str):
    """This was an unhandled ValueError out of ``hash_password``."""
    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(admin_token),
        json=_body("A" * (MAX_PASSWORD_BYTES + 1)),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_does_not_impose_composition_rules(client: AsyncClient, admin_token: str):
    """Length is the control; no forced symbol/digit classes (NIST 800-63B).

    Pinned so nobody "hardens" this into the mix-of-four-classes rule that
    pushes people to Password1! and back to reuse.
    """
    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(admin_token),
        json=_body("correcthorsebatterystaple"),
    )
    assert resp.status_code == 201


# ---- The unauthenticated path ----


@pytest.mark.asyncio
async def test_login_with_over_length_password_is_401_not_500(
    client: AsyncClient, sample_user: UserRow
):
    """The pre-auth crash. Anyone could reach this with no credentials at all."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": "A" * 200},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_over_length_on_unknown_user_is_also_401(client: AsyncClient):
    """No user row involved — the crash was in the primitive, not the lookup."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "nobody_at_all", "password": "A" * 200},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_a_provisioned_user_can_actually_log_in(client: AsyncClient, admin_token: str):
    """End to end: the form's output is a working credential, not just a 201."""
    body = _body(GOOD_PASSWORD)
    created = await client.post(
        "/api/v1/auth/register", headers=auth_header(admin_token), json=body
    )
    assert created.status_code == 201

    login = await client.post(
        "/api/v1/auth/login",
        json={"username": body["username"], "password": GOOD_PASSWORD},
    )
    assert login.status_code == 200
