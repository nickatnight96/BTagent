"""Every TypeScript union that mirrors a shared Python enum lists the same values.

The frontend re-declares a large part of ``btagent_shared.types`` as string
literal unions, because there is no code generation between the two. Nothing
checked that the copies matched, so they drifted — silently, and only in the
direction that hurts: Python gains a value, the browser's copy does not, and
the type system now *disagrees with the data the API actually sends*.

Four such divergences were live when this guard was written, all four with the
same shape — a hunt vertical or IOC kind that ships on the backend and cannot
be named on the frontend:

* ``HuntDomain`` was missing ``email`` / ``deception`` / ``ndr``;
* ``HuntSource`` was missing ``email_security`` / ``deception`` / ``ndr``;
* ``IOCType`` was missing ``registry_key`` / ``user_agent`` / ``mutex`` /
  ``process_name``;
* ``IdentityProvider`` was missing ``duo`` (Cisco Duo, a shipped connector).

The deception, email and NDR hunts stamp those exact ``domain`` / ``source``
values on **every** finding they emit, and those findings land in the same
triage inbox the frontend renders. The failure is quiet rather than loud —
nothing crashes, because the one exhaustive lookup (``IOCNotebook``'s
``TYPE_LABELS``) happens to carry a ``?? ioc.type`` fallback — but TypeScript
actively *rejects* correct code: ``d === "email"`` on a ``HuntDomain`` fails to
compile with "no overlap", which pushes whoever hits it toward a cast instead
of a fix. A ``Record<HuntDomain, …>`` added tomorrow would silently miss three
cases.

This is a ratchet in the same family as ``test_incomplete_run_parity`` (which
locks one such pair by hand). It generalises that: any Python ``StrEnum`` in
``shared/btagent_shared/types`` whose *name* also exists as a string-literal
union in ``frontend/src/types`` must agree with it, member for member.

Name-matching alone left a hole, documented when that half shipped: a union
that renames the concept, or mirrors a backend value set that was never made an
enum, is invisible to it. Eleven of the forty TS unions sat in that hole. They
are now classified explicitly — ``RENAMED_MIRRORS``, ``CONSTANT_BACKED``,
``SUBSET_OF``, ``FRONTEND_ONLY`` — and :func:`test_every_ts_union_is_classified`
fails on any union that is in none of them, so the hole cannot grow back.

All eleven agreed with their backend counterparts when they were classified;
unlike the four above, this pass found no live divergence. Its value is the
ratchet, and the fact that the riskiest category is now covered at all:
``CONSTANT_BACKED`` unions mirror values the backend declares as module
constants and types as bare ``str``, so neither mypy nor Pydantic constrains
them and the TS union is the only place the set is written down as a set.

Every classification resolves its expected values by **importing the live
Python**, never by restating them. A registry that hardcoded the values would
agree with itself forever and detect nothing.

The union parser left a second hole, and it hid the worst drift in the repo:
it only ever looked at ``export type X = "a" | "b"``. Everything declared as
``export enum`` — twelve of them, including all of ``config.ts`` — was never
read. Extending the scan to that form (``_ts_enums``, merged into
``_ts_value_sets``) immediately failed on four live divergences:

* ``InvestigationStatus`` named ``running`` / ``awaiting_hitl`` / ``completed``
  / ``stopped``, none of which the API has ever written, and was missing the
  seven statuses it does. The list filter sends the pill value straight to
  ``GET /investigations?status=`` for an exact string compare, so six of the
  ten role defaults preselected a filter that matched nothing — those personas
  landed on a permanently empty punch list.
* ``TLP`` held display text (``"AMBER+STRICT"``, ``"CLEAR"``) where the API
  expects ``amber_strict`` / ``white``, with one caller lowercasing on the way
  out; that covered three of the five levels and 422'd the other two.
* ``UserRole`` carried ``viewer``, which exists nowhere in the backend.
* ``StepExecutionStatus`` named ``skipped`` and ``waiting_hitl`` (never
  written) while missing ``rejected`` and ``partially_failed`` (both written),
  so a rejected HITL gate rendered as "pending".

Still not covered, so a pass here is not mistaken for proof: a backend value
set with no TS declaration at all is invisible in both directions, and a
declaration whose values are assembled at runtime rather than written as
literals is not parsed.
"""

from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_PY_TYPES = _REPO / "shared" / "btagent_shared" / "types"
_TS_TYPES = _REPO / "frontend" / "src" / "types"

#: Pairs that share a name but are intentionally NOT the same set.
#:
#: Ships empty, and that is the point: every same-named pair currently agrees.
#: An entry here is a claim that a TS union deliberately diverges from the
#: Python enum it shadows, and needs the reason written down — "the frontend
#: does not render X yet" is not one, because the API still sends X.
INTENTIONAL_DIVERGENCE: dict[str, str] = {}

# --------------------------------------------------------------------------- #
# Unions the name-match cannot see
#
# #580 shipped the name-matched half and documented the hole it leaves: a TS
# union that renames the concept, or mirrors a backend value set that is not a
# StrEnum, is invisible. Eleven of the forty TS unions were in that hole. Each
# is classified below, and `test_every_ts_union_is_classified` fails on a new
# one — so the hole cannot silently grow back.
#
# Every entry resolves its expected values by *importing the live Python*, never
# by restating them here. A registry that hardcoded the values would agree with
# itself forever and detect nothing.
# --------------------------------------------------------------------------- #

#: TS name -> the Python StrEnum it mirrors, when the name-match cannot find it:
#: either the TS name differs, or the enum lives outside ``shared/…/types``
#: (which is all the ``_python_str_enums`` scan walks).
RENAMED_MIRRORS: dict[str, tuple[str, str]] = {
    # The frontend appends "Kind" because `ValidationVerdict` is also the name
    # of a record type in validation.ts.
    "ValidationVerdictKind": ("btagent_shared.types.detection_validation", "ValidationVerdict"),
    # Same name, different home: the WebSocket wire protocol is a backend
    # concern, so these live in the backend rather than the shared package.
    "ClientMessageType": ("btagent_backend.ws.protocol", "ClientMessageType"),
    "ServerMessageType": ("btagent_backend.ws.protocol", "ServerMessageType"),
}

#: TS union -> (module, constant prefix) whose module-level string constants it
#: mirrors. These are backend value sets that were never made enums: the
#: services declare `STATUS_FRESH = "fresh"` and type the field as bare `str`,
#: so there is no enum for the name-match to find and no type to check against.
CONSTANT_BACKED: dict[str, tuple[str, str]] = {
    "CoverageStatus": ("btagent_backend.services.coverage_console_service", "STATUS_"),
    "TelemetryGapReason": ("btagent_backend.services.coverage_console_service", "REASON_"),
    "TelemetryGapSignal": ("btagent_backend.services.coverage_console_service", "SIGNAL_"),
    "HuntPlanRowStatus": ("btagent_backend.services.hunt_plan_service", "STATUS_"),
}

#: TS union -> (shared StrEnum, why it is a proper subset).
#: Checked as a subset, not equality — but still checked, so a value that stops
#: existing upstream cannot linger here.
SUBSET_OF: dict[str, tuple[str, str, str]] = {
    "BrokenRuleState": (
        "btagent_shared.types.huntpack",
        "HuntRuleState",
        "the Coverage Console lists only rules that are *broken*; the healthy "
        "states (clean / firing_as_expected) are absent from the list by design",
    ),
}

#: TS unions with no backend counterpart at all — pure UI vocabulary.
#: The bar for this list: the API never sends the value. "The frontend invented
#: it to drive a tab strip or a sort control" qualifies; "the backend sends it
#: but we typed it locally" does not, and belongs in one of the lists above.
FRONTEND_ONLY: dict[str, str] = {
    "CloudTab": "which tab the Cloud Hunts page is showing",
    "DashboardSection": "which dashboard pane is expanded",
    "IOCSortField": "client-side sort column for the IOC table",
    "SortDirection": "client-side sort direction",
    "EnrichmentStatus": (
        "per-source enrichment display state in IOCDetailPanel; no "
        "enrichment_status field exists on any API response"
    ),
}

# A parser this simple could silently match nothing and pass. These floors are
# set below the real counts at the time of writing (80 Python enums / 39 TS
# unions / 12 TS enums / 38 pairs) so ordinary additions do not trip them, but
# a parser that breaks outright does.
#
# ``_MIN_TS_ENUMS`` earns its keep: without it, an enum parser that returned
# nothing would still leave 29 union-only pairs, comfortably above
# ``_MIN_PAIRS`` — so the whole `export enum` half could go dark and every
# check would still report green.
_MIN_PY_ENUMS = 60
_MIN_TS_UNIONS = 30
_MIN_TS_ENUMS = 10
_MIN_PAIRS = 32


def _python_str_enums() -> dict[str, tuple[set[str], str]]:
    """``{EnumName: ({values}, source file)}`` for every StrEnum in shared types."""
    found: dict[str, tuple[set[str], str]] = {}
    for path in sorted(_PY_TYPES.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(isinstance(b, ast.Name) and b.id == "StrEnum" for b in node.bases):
                continue
            values = {
                stmt.value.value
                for stmt in node.body
                if isinstance(stmt, ast.Assign)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            }
            if values:
                found[node.name] = (values, path.name)
    return found


def _ts_literal_unions() -> dict[str, tuple[set[str], str]]:
    """``{TypeName: ({values}, source file)}`` for every exported string-literal union.

    Only unions made *entirely* of string literals are collected; anything with
    a referenced type in it (``HuntRuleState | "never_run"``) is not a mirror
    and is skipped rather than half-parsed.
    """
    found: dict[str, tuple[set[str], str]] = {}
    pattern = re.compile(r"export type (\w+)\s*=\s*((?:\s*\|?\s*\"[^\"]+\")+)\s*;")
    for path in sorted(_TS_TYPES.glob("*.ts")):
        for match in pattern.finditer(path.read_text()):
            values = set(re.findall(r'"([^"]+)"', match.group(2)))
            if values:
                found[match.group(1)] = (values, path.name)
    return found


def _ts_enums() -> dict[str, tuple[set[str], str]]:
    """``{EnumName: ({values}, source file)}`` for every exported TS ``enum``.

    The union parser above could not see these, and that hole hid the worst
    divergence in the codebase: ``config.ts`` declares ``export enum
    InvestigationStatus`` whose members were ``running`` / ``awaiting_hitl`` /
    ``completed`` / ``stopped`` — four values the API has never sent — while
    missing seven it does. The list filter compares those values against
    ``investigations.status`` with an exact string match, so six of the ten
    role defaults preselected a pill that matched nothing.

    Only string-valued members are collected; a numeric or computed member
    makes the enum not a value mirror, so it is skipped rather than
    half-parsed.
    """
    found: dict[str, tuple[set[str], str]] = {}
    block = re.compile(r"export enum (\w+)\s*\{(.*?)\n\}", re.DOTALL)
    member = re.compile(r"^\s*\w+\s*=\s*\"([^\"]+)\"\s*,?\s*$", re.MULTILINE)
    for path in sorted(_TS_TYPES.glob("*.ts")):
        for match in block.finditer(path.read_text()):
            values = set(member.findall(match.group(2)))
            if values:
                found[match.group(1)] = (values, path.name)
    return found


def _ts_value_sets() -> dict[str, tuple[set[str], str]]:
    """Every TS name that declares a fixed set of strings — union or ``enum``.

    Both forms are mirrors of a backend vocabulary and both drift the same way,
    so every check in this file runs over the merged view.
    """
    unions, enums = _ts_literal_unions(), _ts_enums()
    # A name may legitimately be declared both ways — `Severity` is an enum in
    # config.ts and a union in hunt.ts. That is fine only while the two agree;
    # if they drift, the merged view below would hide one of them and the
    # backend check would silently grade the wrong declaration.
    for name in sorted(set(unions) & set(enums)):
        union_values, union_file = unions[name]
        enum_values, enum_file = enums[name]
        assert union_values == enum_values, (
            f"{name} is declared twice on the frontend and the two disagree:\n"
            f"  union in {union_file}: {sorted(union_values)}\n"
            f"  enum in  {enum_file}: {sorted(enum_values)}\n"
            "Collapse them to one declaration, or make them match."
        )
    return {**unions, **enums}


def _pairs() -> list[str]:
    return sorted(set(_python_str_enums()) & set(_ts_value_sets()))


def test_parsers_find_a_realistic_amount():
    """Guard the guard: an empty parse would make every parity check vacuous."""
    py, unions, enums, pairs = (
        _python_str_enums(),
        _ts_literal_unions(),
        _ts_enums(),
        _pairs(),
    )
    assert len(py) >= _MIN_PY_ENUMS, f"only parsed {len(py)} Python StrEnums"
    assert len(unions) >= _MIN_TS_UNIONS, f"only parsed {len(unions)} TypeScript unions"
    assert len(enums) >= _MIN_TS_ENUMS, f"only parsed {len(enums)} TypeScript enums"
    assert len(pairs) >= _MIN_PAIRS, f"only matched {len(pairs)} name pairs"


def test_parsers_read_a_known_union_correctly():
    """Pin one union pair end to end, so a parser that returns junk cannot pass."""
    py, ts = _python_str_enums(), _ts_literal_unions()
    assert py["Severity"][0] == {"critical", "high", "medium", "low", "info"}
    assert ts["Severity"][0] == {"critical", "high", "medium", "low", "info"}


def test_parsers_read_a_known_ts_enum_correctly():
    """Same pin for the `export enum` half — the form that went unchecked.

    ``InvestigationStatus`` is the one this parser was written for, so it is
    the one worth pinning: a regex that matched the block but dropped members
    would leave the pair "agreeing" on a subset and report green.
    """
    py, ts = _python_str_enums(), _ts_enums()
    expected = {
        "pending",
        "triaging",
        "investigating",
        "paused",
        "paused_hitl",
        "contained",
        "remediated",
        "closed",
        "failed",
        "cancelled",
        "archived",
    }
    assert py["InvestigationStatus"][0] == expected
    assert ts["InvestigationStatus"][0] == expected
    assert ts["InvestigationStatus"][1] == "config.ts"


@pytest.mark.parametrize("name", _pairs())
def test_ts_union_matches_its_python_enum(name: str):
    py_values, py_file = _python_str_enums()[name]
    ts_values, ts_file = _ts_value_sets()[name]

    if name in INTENTIONAL_DIVERGENCE:
        pytest.skip(f"documented divergence: {INTENTIONAL_DIVERGENCE[name]}")

    missing_in_ts = sorted(py_values - ts_values)
    extra_in_ts = sorted(ts_values - py_values)
    assert not missing_in_ts and not extra_in_ts, (
        f"{name} has drifted between {py_file} and {ts_file}.\n"
        f"  the API can send, but the frontend type cannot name: {missing_in_ts}\n"
        f"  the frontend type names, but the API never sends:    {extra_in_ts}\n"
        "Update the TypeScript union to match, or add a documented entry to "
        "INTENTIONAL_DIVERGENCE explaining why the two must differ."
    )


def _import_attr(module_path: str, name: str):
    module = importlib.import_module(module_path)
    assert hasattr(module, name), f"{module_path} has no {name}"
    return getattr(module, name)


def _constants_with_prefix(module_path: str, prefix: str) -> set[str]:
    """Module-level ``PREFIX_*`` string constants, resolved from the live module."""
    module = importlib.import_module(module_path)
    return {
        value
        for name, value in vars(module).items()
        if name.startswith(prefix) and isinstance(value, str)
    }


@pytest.mark.parametrize("ts_name", sorted(RENAMED_MIRRORS))
def test_renamed_mirror_matches_its_enum(ts_name: str):
    """A union that renames the concept must still track it."""
    module_path, enum_name = RENAMED_MIRRORS[ts_name]
    expected = {member.value for member in _import_attr(module_path, enum_name)}
    actual, ts_file = _ts_value_sets()[ts_name]
    assert actual == expected, (
        f"{ts_name} ({ts_file}) has drifted from {enum_name} in {module_path}.\n"
        f"  missing in TS: {sorted(expected - actual)}\n"
        f"  extra in TS:   {sorted(actual - expected)}"
    )


@pytest.mark.parametrize("ts_name", sorted(CONSTANT_BACKED))
def test_constant_backed_union_matches_the_backend_constants(ts_name: str):
    """Value sets the backend declares as constants rather than an enum.

    These are the least protected of all: the Python field is typed ``str``, so
    neither mypy nor Pydantic checks the value, and the TS union is the only
    place the set is written down as a set. Adding a fifth ``STATUS_`` constant
    on the backend is a one-line change that nothing else notices.
    """
    module_path, prefix = CONSTANT_BACKED[ts_name]
    expected = _constants_with_prefix(module_path, prefix)
    actual, ts_file = _ts_value_sets()[ts_name]
    assert expected, f"no {prefix}* constants found in {module_path}"
    assert actual == expected, (
        f"{ts_name} ({ts_file}) has drifted from {prefix}* in {module_path}.\n"
        f"  the backend can send, the union cannot name: {sorted(expected - actual)}\n"
        f"  the union names, the backend never sends:    {sorted(actual - expected)}"
    )


@pytest.mark.parametrize("ts_name", sorted(SUBSET_OF))
def test_subset_union_stays_a_subset(ts_name: str):
    """A deliberate subset must remain a subset — and a real one."""
    module_path, enum_name, _reason = SUBSET_OF[ts_name]
    superset = {member.value for member in _import_attr(module_path, enum_name)}
    actual, ts_file = _ts_value_sets()[ts_name]
    assert actual <= superset, (
        f"{ts_name} ({ts_file}) names values {enum_name} does not have: {sorted(actual - superset)}"
    )
    # If it ever equals the superset it is not a subset any more, and belongs
    # in the ordinary name-matched (or renamed) path where equality is checked.
    assert actual < superset, (
        f"{ts_name} now covers all of {enum_name}; move it out of SUBSET_OF "
        "so it is checked for equality instead."
    )


def test_every_ts_union_is_classified():
    """The ratchet: a new TS union must be put in exactly one bucket.

    This is what keeps #580's documented blind spot from growing back. Without
    it, someone adding a union that mirrors a backend value set gets no signal
    at all — which is precisely how the eleven unclassified ones accumulated.
    """
    name_matched = set(_pairs())
    classified = (
        name_matched
        | set(RENAMED_MIRRORS)
        | set(CONSTANT_BACKED)
        | set(SUBSET_OF)
        | set(FRONTEND_ONLY)
    )
    unclassified = sorted(set(_ts_value_sets()) - classified)
    assert not unclassified, (
        f"unclassified TypeScript unions: {unclassified}.\n"
        "Each must be one of: same-named as a shared StrEnum (checked "
        "automatically), RENAMED_MIRRORS, CONSTANT_BACKED, SUBSET_OF, or "
        "FRONTEND_ONLY. Putting a backend-sent value in FRONTEND_ONLY to "
        "silence this is the mistake the whole file exists to prevent."
    )


def test_no_union_is_classified_twice():
    """Overlapping buckets would mean two different checks claim the same union."""
    buckets = {
        "name-matched": set(_pairs()),
        "RENAMED_MIRRORS": set(RENAMED_MIRRORS),
        "CONSTANT_BACKED": set(CONSTANT_BACKED),
        "SUBSET_OF": set(SUBSET_OF),
        "FRONTEND_ONLY": set(FRONTEND_ONLY),
    }
    seen: dict[str, str] = {}
    for bucket, names in buckets.items():
        for name in names:
            assert name not in seen, (
                f"{name} is in both {seen[name]} and {bucket}; a union has "
                "exactly one source of truth"
            )
            seen[name] = bucket


def test_classification_lists_only_hold_real_unions():
    """No bucket may name a union that no longer exists."""
    known = set(_ts_value_sets())
    for label, names in (
        ("RENAMED_MIRRORS", set(RENAMED_MIRRORS)),
        ("CONSTANT_BACKED", set(CONSTANT_BACKED)),
        ("SUBSET_OF", set(SUBSET_OF)),
        ("FRONTEND_ONLY", set(FRONTEND_ONLY)),
    ):
        stale = sorted(names - known)
        assert not stale, f"{label} names unions that no longer exist: {stale}"


def test_divergence_list_only_holds_real_pairs():
    """The exemption list may not rot into names that no longer exist."""
    stale = sorted(set(INTENTIONAL_DIVERGENCE) - set(_pairs()))
    assert not stale, (
        f"INTENTIONAL_DIVERGENCE names pairs that no longer exist: {stale}. "
        "Remove them — a ratchet's exemption list may only shrink."
    )
