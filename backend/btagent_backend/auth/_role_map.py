"""Shared IdP-role → BTagent-role mapping (used by OIDC and SAML SSO).

Both SSO protocols carry the user's group/role membership as one-or-more
string values (an OIDC claim, a SAML attribute). The mapping rule is identical:
the first candidate value that has an entry in ``role_map`` wins; otherwise the
provider's ``default_role`` is used. The result is validated against the
BTagent ``UserRole`` enum so a typo'd ``role_map`` can never grant an
invalid/elevated role — an unrecognised mapped value falls back to
``default_role``.

Keeping this in one place means the OIDC and SAML layers can't drift apart on
the (security-sensitive) role-resolution semantics.
"""

from __future__ import annotations

from collections.abc import Iterable


def resolve_role(
    *,
    role_map: dict[str, str],
    default_role: str,
    candidate_values: Iterable[str],
) -> str:
    """Resolve a BTagent role from IdP-supplied role/group values.

    ``candidate_values`` is iterated in order; the first one with a ``role_map``
    entry wins. Both the mapped value and ``default_role`` are coerced against
    the ``UserRole`` enum — anything unrecognised collapses to ``default_role``
    (and if ``default_role`` itself is invalid, to ``analyst``).
    """
    from btagent_shared.types.enums import UserRole

    valid_roles = {r.value for r in UserRole}
    safe_default = default_role if default_role in valid_roles else UserRole.ANALYST.value

    def _coerce(role: str) -> str:
        return role if role in valid_roles else safe_default

    for value in candidate_values:
        mapped = role_map.get(value)
        if mapped is not None:
            return _coerce(mapped)

    return safe_default
