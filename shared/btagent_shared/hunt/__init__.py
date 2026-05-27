"""Pure-logic cores for the Phase 6 threat-hunting subsystem.

Everything in this subpackage is dependency-free (no DB, no network, no
LLM) and operates on the :mod:`btagent_shared.types` models. That keeps
each function trivially unit-testable and lets it be reused verbatim as an
engine ``Node`` body when Phase 6 migrates onto the engine runtime.
"""
