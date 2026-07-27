"""Detection Engineer plugin package (#113 "do both").

Agentic CTI → Detection persona: prose intel report → behavioral TTP tuples
(CTIExtractor) → drafted Sigma rules (RuleDrafter) → data-source reconciliation
against connected connectors (DataSourceMatcher). Complements the deterministic
STIX → Sigma pipeline; HITL-gated before any detection-repo PR.
"""

from btagent_agents.plugins.detection_engineer.plugin import (
    DetectionEngineerPlugin,
    plugin,
)

__all__ = ["DetectionEngineerPlugin", "plugin"]
