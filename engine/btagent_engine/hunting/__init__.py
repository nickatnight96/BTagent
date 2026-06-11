"""Hunt Pack Runner core (#112) — Sigma packs, transpile, execution.

Transpile/execute slice only: load a versioned pack of Sigma rules from a
directory, transpile each rule to the four connected SIEM backends, run the
queries through the existing engine integration nodes, and return raw hits
as in-memory :class:`SigmaHit` objects.

Persistence (HuntFinding rows, run history) is the #112 integration PR's
job: it converts ``SigmaHit`` -> ``HuntFinding`` via
``hunt_triage_service.ingest_findings``.
"""

from btagent_engine.hunting.pack import (
    BUILTIN_PACKS_DIR,
    HuntPack,
    HuntPackRule,
    PackLoadError,
    load_builtin_pack,
    load_pack,
)
from btagent_engine.hunting.runner import (
    BackendRunResult,
    PackRunResult,
    RuleRunResult,
    SigmaHit,
    SigmaHitEntity,
    run_pack,
)
from btagent_engine.hunting.transpile import (
    SUPPORTED_BACKENDS,
    SigmaBackendName,
    SigmaTranspileError,
    UnsupportedSigmaRuleError,
    transpile,
)

__all__ = [
    "BUILTIN_PACKS_DIR",
    "BackendRunResult",
    "HuntPack",
    "HuntPackRule",
    "PackLoadError",
    "PackRunResult",
    "RuleRunResult",
    "SUPPORTED_BACKENDS",
    "SigmaBackendName",
    "SigmaHit",
    "SigmaHitEntity",
    "SigmaTranspileError",
    "UnsupportedSigmaRuleError",
    "load_builtin_pack",
    "load_pack",
    "run_pack",
    "transpile",
]
