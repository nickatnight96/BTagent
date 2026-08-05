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

Matching is by name, which is a deliberate limitation: a TS union that renames
the concept is invisible here. What the guard does buy is that the pairs which
*do* line up cannot drift, and that a new value added to a mirrored Python enum
fails at PR time rather than a release later.
"""

from __future__ import annotations

import ast
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

# A parser this simple could silently match nothing and pass. These floors are
# set below the real counts at the time of writing (80 enums / 40 unions / 29
# pairs) so ordinary additions do not trip them, but a parser that breaks
# outright does.
_MIN_PY_ENUMS = 60
_MIN_TS_UNIONS = 30
_MIN_PAIRS = 25


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


def _pairs() -> list[str]:
    return sorted(set(_python_str_enums()) & set(_ts_literal_unions()))


def test_parsers_find_a_realistic_amount():
    """Guard the guard: an empty parse would make every parity check vacuous."""
    py, ts, pairs = _python_str_enums(), _ts_literal_unions(), _pairs()
    assert len(py) >= _MIN_PY_ENUMS, f"only parsed {len(py)} Python StrEnums"
    assert len(ts) >= _MIN_TS_UNIONS, f"only parsed {len(ts)} TypeScript unions"
    assert len(pairs) >= _MIN_PAIRS, f"only matched {len(pairs)} name pairs"


def test_parsers_read_a_known_enum_correctly():
    """Pin one pair end to end, so a parser that returns junk cannot pass."""
    py, ts = _python_str_enums(), _ts_literal_unions()
    assert py["Severity"][0] == {"critical", "high", "medium", "low", "info"}
    assert ts["Severity"][0] == {"critical", "high", "medium", "low", "info"}


@pytest.mark.parametrize("name", _pairs())
def test_ts_union_matches_its_python_enum(name: str):
    py_values, py_file = _python_str_enums()[name]
    ts_values, ts_file = _ts_literal_unions()[name]

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


def test_divergence_list_only_holds_real_pairs():
    """The exemption list may not rot into names that no longer exist."""
    stale = sorted(set(INTENTIONAL_DIVERGENCE) - set(_pairs()))
    assert not stale, (
        f"INTENTIONAL_DIVERGENCE names pairs that no longer exist: {stale}. "
        "Remove them — a ratchet's exemption list may only shrink."
    )
