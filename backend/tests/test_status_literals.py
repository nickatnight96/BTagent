"""Status and state comparisons name their enum instead of a bare string.

A literal like ``row.status == "failed"`` compiles, passes review, and passes
every test — while saying nothing about *which* vocabulary it belongs to.
``"failed"`` is a member of six enums in this codebase (``ContainmentStatus``,
``HuntRunStatus``, ``InvestigationStatus``, ``PlaybookStatus``,
``StepExecutionStatus``, ``WorkflowRunStatus``). ``"proposed"`` is a member of
six more — including both ``state`` *and* ``pr_outcome`` on the same
``DetectionProposalRow``, where it means two different things.

This is not hypothetical here. ``handover_service`` carries a comment
recording that it once rolled up on ``"running"`` and ``"awaiting_approval"``,
strings that exist in no ``InvestigationStatus`` — so genuinely active
incidents were silently missing from the shift handover (#387). The literal
compared equal to nothing and nothing complained. That same file still
compared ``HuntFindingRow.state`` against a bare ``("new", "clustered")``
until this guard was written.

Naming the enum does not make the code correct — a wrong member is still
wrong. What it does is make the claim *checkable*: ``HuntFindingState.NEW``
fails loudly at import if the member is renamed or removed, where ``"new"``
just quietly stops matching. Ruff's ``F821`` covers the undefined-name half;
this covers the half where the string is real but unattributed.

What is checked
---------------
Comparisons against an attribute named ``status`` or ``state`` — via ``==``,
``!=``, ``.in_()`` or ``.not_in()`` — where the literal happens to be a member
of some shared ``StrEnum``. Those are the ones that look fine and carry a
hidden contract.

What is NOT checked, so a pass isn't read as more than it is
------------------------------------------------------------
* **Other attribute names.** ``pr_outcome``, ``disposition``, ``verdict`` and
  friends carry vocabularies too. They are not scanned, because widening the
  attribute list without widening the fixes would just produce a long
  exemption list — the honest shape for a follow-up, not for this guard.
* **Literals that match no enum.** A typo'd ``"faield"`` is invisible here.
  That is the deeper problem and it needs typed columns, not a scanner.
* **Values, not correctness.** Naming ``HuntRunStatus.COMPLETED`` where the
  logic wanted ``FAILED`` is a bug this cannot see.
* **Non-backend packages.** Only ``backend/btagent_backend`` is walked.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_BACKEND = _REPO / "backend" / "btagent_backend"

#: ``"path:line:literal" -> why the bare string stays.``
#:
#: Ships empty. An entry is a claim that a status literal is clearer than the
#: enum member it shadows, which is a hard case to make.
LITERAL_EXEMPT: dict[str, str] = {}

#: Attributes whose comparands are a status vocabulary.
_STATUS_ATTRS = frozenset({"status", "state"})

# A scan that resolved no enum values would pass vacuously. The real count is
# in the hundreds; this floor only catches a scan that broke outright.
_MIN_ENUM_VALUES = 100


@lru_cache(maxsize=1)
def _enum_values() -> dict[str, tuple[str, ...]]:
    """``{"value": ("EnumA", "EnumB", …)}`` across shared types.

    A value appearing under several enums is the interesting case, not a
    problem with the scan — it is precisely what makes a bare literal
    ambiguous.
    """
    import btagent_shared.types as shared_types

    found: dict[str, set[str]] = {}
    for module_info in pkgutil.iter_modules(shared_types.__path__):
        module = importlib.import_module(f"btagent_shared.types.{module_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, StrEnum) and obj is not StrEnum:
                for member in obj:
                    found.setdefault(member.value, set()).add(obj.__name__)
    return {value: tuple(sorted(names)) for value, names in found.items()}


def _bare_status_literals() -> list[tuple[str, str, tuple[str, ...]]]:
    """``(location, literal, enums it belongs to)`` for every unattributed compare."""
    values = _enum_values()
    hits: list[tuple[str, str, tuple[str, ...]]] = []

    def _record(path: Path, node: ast.Constant) -> None:
        if not isinstance(node.value, str) or node.value not in values:
            return
        rel = path.relative_to(_REPO)
        hits.append((f"{rel}:{node.lineno}", node.value, values[node.value]))

    for path in sorted(_BACKEND.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            # `<row>.status.in_([...])` / `.not_in([...])`
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"in_", "not_in"}
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr in _STATUS_ATTRS
            ):
                for arg in node.args:
                    for element in getattr(arg, "elts", []):
                        if isinstance(element, ast.Constant):
                            _record(path, element)
            # `<row>.status == "..."` / `!= "..."`
            if (
                isinstance(node, ast.Compare)
                and isinstance(node.left, ast.Attribute)
                and node.left.attr in _STATUS_ATTRS
            ):
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Constant):
                        _record(path, comparator)
    return hits


def test_the_scan_resolves_a_realistic_number_of_enum_values():
    """Guard the guard: no resolved values would make the check below vacuous."""
    values = _enum_values()
    assert len(values) >= _MIN_ENUM_VALUES, f"only resolved {len(values)} enum values"


def test_the_scan_sees_the_ambiguity_it_exists_for():
    """Pin the collisions that motivate this file.

    If these stop resolving, the scan has lost the signal it is built on and
    would report clean for the wrong reason.
    """
    values = _enum_values()
    assert len(values["failed"]) >= 5, values["failed"]
    # Two different ProposalState enums exist (detection_proposal and
    # pattern_hunt), and PROutcome uses the same word for a different stage.
    assert "PROutcome" in values["proposed"]
    assert len(values["proposed"]) >= 3, values["proposed"]


def test_status_comparisons_name_their_enum():
    """The ratchet: a status literal must say which vocabulary it belongs to."""
    bare = [
        (location, literal, enums)
        for location, literal, enums in _bare_status_literals()
        if f"{location}:{literal}" not in LITERAL_EXEMPT
    ]
    assert not bare, (
        "These status/state comparisons use a bare string that is a member of a "
        "shared enum:\n  "
        + "\n  ".join(
            f"{location}: {literal!r} — a member of {', '.join(enums)}"
            for location, literal, enums in bare
        )
        + "\n\nName the enum member instead. A literal compares equal to nothing "
        "if the vocabulary moves, and says nothing about which of several "
        "same-valued enums it means (#387)."
    )


def test_exemption_list_only_holds_live_entries():
    """The exemption list may only shrink."""
    live = {f"{location}:{literal}" for location, literal, _ in _bare_status_literals()}
    stale = sorted(set(LITERAL_EXEMPT) - live)
    assert not stale, (
        f"LITERAL_EXEMPT names comparisons that no longer exist: {stale}. "
        "Remove them — a ratchet's exemption list may only shrink."
    )
