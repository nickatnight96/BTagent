"""Pytest configuration for the agents test suite.

Ensures the *current worktree* copy of ``btagent_agents`` (not any globally
installed editable copy that may point at a sibling worktree) is the one
being imported. Without this, agents cohabiting in ``.claude/worktrees`` end
up importing each other's stale code and tests fail with bewildering
``ModuleNotFoundError``\\s for newly-added submodules.
"""

from __future__ import annotations

import sys
from pathlib import Path

_AGENTS_ROOT = Path(__file__).resolve().parent.parent
_SHARED_ROOT = _AGENTS_ROOT.parent / "shared"
_ENGINE_ROOT = _AGENTS_ROOT.parent / "engine"

for path in (_AGENTS_ROOT, _SHARED_ROOT, _ENGINE_ROOT):
    p = str(path)
    if p not in sys.path:
        sys.path.insert(0, p)

# Drop any pre-imported stale btagent_agents / btagent_engine modules so the
# path-prepended copy wins on first import.
for mod in [
    m
    for m in list(sys.modules)
    if m.startswith("btagent_agents") or m.startswith("btagent_engine")
]:
    del sys.modules[mod]
