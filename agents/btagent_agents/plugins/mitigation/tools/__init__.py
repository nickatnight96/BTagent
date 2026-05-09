"""Mitigation plugin tools."""

from btagent_agents.plugins.mitigation.tools.remediation_generator import (
    generate_detection_content,
    generate_hardening_recommendations,
    generate_remediation,
)

__all__ = [
    "generate_remediation",
    "generate_detection_content",
    "generate_hardening_recommendations",
]
