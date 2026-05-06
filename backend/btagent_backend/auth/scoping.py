"""Route-level resource scoping helpers (AUTH-B1).

These helpers close the IDOR findings flagged in audit Wave 2: every route
that returns or mutates an investigation / IOC / evidence row must call
``assert_can_access_*`` after fetching the row but before returning it
(read paths) or applying the mutation (write paths).

Why 404 instead of 403
----------------------
When a caller is *out of scope* for a row (wrong tenant, or analyst trying
to touch another analyst's case) we deliberately raise ``HTTPException(404)``
rather than 403. A 403 would tell the attacker "this ID exists, you just
can't read it" — that's an existence oracle, which is enough to enumerate
case identifiers across tenants. 404 is indistinguishable from "no such
row" and therefore leaks nothing.

(Authentication failures still come back as 401 from the auth dependency;
the 404-not-403 rule only applies to scoping checks against rows that *do*
exist in the DB.)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, status

if TYPE_CHECKING:  # pragma: no cover - import only for type hints
    from btagent_backend.auth.middleware import CurrentUser
    from btagent_backend.db.models import EvidenceRow, InvestigationRow, IOCRow


# Roles that can see / touch every resource in their own org.
_ORG_WIDE_ROLES = frozenset({"admin", "incident_commander", "senior_analyst"})


def _deny() -> HTTPException:
    """Return the 404 used to mask out-of-scope access (see module docstring)."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Not found",
    )


def assert_can_access_investigation(
    user: CurrentUser,
    investigation: InvestigationRow,
    *,
    write: bool = False,
) -> None:
    """Raise 404 if ``user`` may not access ``investigation``.

    Rules
    -----
    * Cross-org access is *always* denied, regardless of role.
    * ``admin``, ``incident_commander``, and ``senior_analyst`` may read
      and write any investigation **within their own org**.
    * ``analyst`` may read and write only investigations where
      ``assigned_to == user.id`` AND ``investigation.org_id == user.org_id``.

    The ``write`` flag is currently informational — the rule for analysts
    is the same for read and write — but it's part of the API so callers
    document intent and so future policy changes (e.g. read-only viewer
    role) have a hook.
    """
    # Tenant boundary first: cross-org never allowed.
    if getattr(investigation, "org_id", None) != user.org_id:
        raise _deny()

    if user.role in _ORG_WIDE_ROLES:
        return

    # Analyst (or any non-org-wide role): must own the investigation.
    if investigation.assigned_to != user.id:
        raise _deny()

    # ``write`` parameter intentionally unused for the analyst path — both
    # read and write require ownership today. Reference it so static
    # analysers don't flag it as dead.
    _ = write


def assert_can_access_ioc(
    user: CurrentUser,
    ioc: IOCRow,
    *,
    investigation: InvestigationRow | None = None,
    write: bool = False,
) -> None:
    """Raise 404 if ``user`` may not access ``ioc``.

    IOC access derives from the parent investigation: if you can access the
    investigation the IOC belongs to, you can access the IOC. The caller may
    pass the already-loaded ``InvestigationRow`` to avoid an extra query;
    when omitted, this helper falls back to the IOC's ``org_id`` (Phase A1
    gives every IOC its own ``org_id`` column) and refuses cross-org access.
    Ownership-by-analyst still requires the parent investigation to be
    supplied — without it, only the org_id check is enforced and analysts
    are denied (fail closed).
    """
    if getattr(ioc, "org_id", None) != user.org_id:
        raise _deny()

    if investigation is not None:
        assert_can_access_investigation(user, investigation, write=write)
        return

    # No parent investigation supplied. Org-wide roles are fine; analysts
    # cannot make the ownership determination, so deny.
    if user.role not in _ORG_WIDE_ROLES:
        raise _deny()


def assert_can_access_evidence(
    user: CurrentUser,
    evidence: EvidenceRow,
    *,
    investigation: InvestigationRow | None = None,
    write: bool = False,
) -> None:
    """Raise 404 if ``user`` may not access ``evidence``.

    Same shape as :func:`assert_can_access_ioc` — evidence inherits scoping
    from its parent investigation. Provided for completeness so future
    evidence routes can reuse the same helper.
    """
    if getattr(evidence, "org_id", None) != user.org_id:
        raise _deny()

    if investigation is not None:
        assert_can_access_investigation(user, investigation, write=write)
        return

    if user.role not in _ORG_WIDE_ROLES:
        raise _deny()


__all__ = [
    "assert_can_access_evidence",
    "assert_can_access_investigation",
    "assert_can_access_ioc",
]
