"""Pytest configuration for the engine test suite.

Mirrors agents/tests/conftest.py: prepends the local engine + shared
package paths to ``sys.path`` so the current worktree's source wins over
any globally-installed editable copy that may point at a sibling
worktree (the "stale btagent_engine import" trap from the cross-worktree
agent runs in Phase 0 / auth-hardening).
"""

from __future__ import annotations

import sys
from pathlib import Path

_ENGINE_ROOT = Path(__file__).resolve().parent.parent
_SHARED_ROOT = _ENGINE_ROOT.parent / "shared"

for path in (_ENGINE_ROOT, _SHARED_ROOT):
    p = str(path)
    if p not in sys.path:
        sys.path.insert(0, p)

# Drop any pre-imported stale btagent_engine modules so the path-prepended
# copy wins on first import.
for mod in [m for m in list(sys.modules) if m.startswith("btagent_engine")]:
    del sys.modules[mod]
