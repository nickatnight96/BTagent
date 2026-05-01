"""Shared pytest configuration for the agents test suite."""

from __future__ import annotations

import sys
from pathlib import Path

# Make the package importable when tests are run from the agents/ directory.
_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))
