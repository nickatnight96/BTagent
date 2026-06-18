"""Pure-logic cores for the Phase 6 threat-hunting subsystem.

Everything in this subpackage is dependency-free (no DB, no network, no
LLM) and operates on the :mod:`btagent_shared.types` models. That keeps
each function trivially unit-testable and lets it be reused verbatim as an
engine ``Node`` body when Phase 6 migrates onto the engine runtime.

Modules
-------
- :mod:`btagent_shared.hunt.behavioral` — Behavioral outlier scoring (#114)
- :mod:`btagent_shared.hunt.huntpack` — Hunt-pack noise-baseline logic (#112)
- :mod:`btagent_shared.hunt.triage` — Finding cluster + suppression matching (#119)
- :mod:`btagent_shared.hunt.schedule` — Hunt schedule helpers
- :mod:`btagent_shared.hunt.identity` — Identity detectors (#116)
"""
