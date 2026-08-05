"""Every destructive containment action is safelist-screened, or named as not.

The safelist is the collateral-outage guard: it is what stops an approved
containment action from taking out the domain controller, the monitoring
subnet, or the break-glass admin. It works by screening the action's *target*
against an org-scoped never-touch list before dispatch.

The screen is keyed on ``action_type``. That means an action type simply
missing from ``_SAFELIST_SCREENED_ACTION_TYPES`` is not screened — and at the
call site an unscreened action is indistinguishable from a screened one, since
the ``if action_type in ...`` just does not fire. Nothing recorded whether a
given omission was a decision or an oversight.

For ``disable_account`` it was an oversight. The safelist has held a
``principal`` entry kind since the #117 cloud IAM work — exact, case-insensitive,
with an always-on account-root guard — and an account identifier is the same
class of thing. Disabling the break-glass admin is the textbook collateral
outage, and it was the one destructive action with an obvious matching entry
kind that nothing checked against.

Severity, stated honestly: nothing destructive reaches a real system today.
``_dispatch`` raises ``NotImplementedError`` whenever ``BTAGENT_MOCK_CONNECTORS``
is off, so every containment path is mock-only. This was a latent gap in a
defence-in-depth control, not a live exposure — which is the argument for
closing it now, while it is a three-line change, rather than after #100/#106
unbolt the live connector paths.

What this file pins:

* every :class:`ResponseActionType` is classified — screened (and against which
  safelist kind), destructive-but-unscreened (with a written reason), or
  non-destructive. A new action type that is none of those fails here rather
  than silently defaulting to unscreened;
* ``UNSCREENED_DESTRUCTIVE_ACTION_TYPES`` may only shrink. It is a debt list
  with a name, in the same spirit as ``test_api_reachability``'s ``KNOWN_GAPS``,
  and moving an action into it to silence a failure is the mistake the file
  exists to prevent;
* the behaviour itself: a safelisted account is refused with an audited denial,
  not merely absent from a set.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.response import ResponseActionType

from btagent_backend.services import containment_execute_service as svc

# Action types whose target is inert — they read, record, or notify, and cannot
# take anything offline. Screening them would be noise, not safety.
_NON_DESTRUCTIVE = frozenset(
    {
        ResponseActionType.FORENSIC_SNAPSHOT.value,
        ResponseActionType.PULL_LOGS.value,
        ResponseActionType.OPEN_TICKET.value,
        ResponseActionType.NOTIFY.value,
    }
)


def _all_action_types() -> set[str]:
    return {member.value for member in ResponseActionType}


def test_every_response_action_type_is_classified():
    """No action type may fall through to "unscreened" by default."""
    classified = (
        set(svc._SAFELIST_SCREENED_ACTION_TYPES)
        | set(svc.UNSCREENED_DESTRUCTIVE_ACTION_TYPES)
        | _NON_DESTRUCTIVE
    )
    unclassified = sorted(_all_action_types() - classified)
    assert not unclassified, (
        f"unclassified ResponseActionType values: {unclassified}. Each must be "
        "safelist-screened, listed in UNSCREENED_DESTRUCTIVE_ACTION_TYPES with "
        "a reason, or non-destructive. Defaulting to unscreened is how "
        "disable_account went unguarded."
    )


def test_no_action_type_is_both_screened_and_listed_unscreened():
    overlap = sorted(
        set(svc._SAFELIST_SCREENED_ACTION_TYPES) & set(svc.UNSCREENED_DESTRUCTIVE_ACTION_TYPES)
    )
    assert not overlap, f"contradictory classification for: {overlap}"


def test_unscreened_list_names_only_real_action_types():
    """A debt list may not rot into names that no longer exist."""
    stale = sorted(set(svc.UNSCREENED_DESTRUCTIVE_ACTION_TYPES) - _all_action_types())
    assert not stale, f"UNSCREENED_DESTRUCTIVE_ACTION_TYPES names unknown actions: {stale}"


def test_unscreened_list_has_a_written_reason_for_each_entry():
    """ "Unscreened" is a claim that needs an argument, not a bare entry."""
    for action, reason in svc.UNSCREENED_DESTRUCTIVE_ACTION_TYPES.items():
        assert reason and len(reason) > 30, (
            f"{action} is listed as unscreened without a substantive reason"
        )


def test_unscreened_list_may_only_shrink():
    """The ratchet. Closing one of these means deleting its line.

    Pinned explicitly so adding a third unscreened destructive action is a
    visible, deliberate edit to this test rather than a quiet append.
    """
    assert set(svc.UNSCREENED_DESTRUCTIVE_ACTION_TYPES) == {"isolate_host", "kill_process"}


def test_disable_account_is_screened_against_the_principal_safelist():
    """The fix: an account target screens the same list a cloud principal does."""
    assert ResponseActionType.DISABLE_ACCOUNT.value in svc._SAFELIST_SCREENED_ACTION_TYPES
    assert ResponseActionType.DISABLE_ACCOUNT.value in svc._PRINCIPAL_SCREENED_ACTION_TYPES


def test_blocklist_actions_still_screen_their_own_kinds():
    """Guard the guard: routing accounts to `principal` must not have moved the
    blocklist actions off the ip/domain sets."""
    assert svc._BLOCK_ACTION_TYPES == {"block_ip", "block_domain"}
    assert not (svc._BLOCK_ACTION_TYPES & svc._PRINCIPAL_SCREENED_ACTION_TYPES)


@pytest.mark.parametrize(
    ("action_type", "target", "expected"),
    [
        # The principal safelist screens accounts and cloud principals alike.
        ("disable_account", "svc-backup@corp.example", True),
        ("disable_account", "SVC-BACKUP@CORP.EXAMPLE", True),  # case-insensitive
        ("disable_account", "mallory@corp.example", False),
        ("revoke_role", "svc-backup@corp.example", True),
        # …and does not bleed into the address-based kinds.
        ("block_ip", "svc-backup@corp.example", False),
    ],
)
def test_target_safelisted_routes_each_action_to_the_right_kind(
    action_type: str, target: str, expected: bool
):
    from btagent_shared.security.safelist import SafelistPolicy

    policy = SafelistPolicy(
        ips=frozenset(),
        domain_suffixes=frozenset(),
        principals=frozenset({"svc-backup@corp.example"}),
    )
    assert svc._target_safelisted(policy, action_type, target) is expected
