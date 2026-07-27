"""Sandbox-enforcement policy for adversary emulation (#118).

Detection-validation wraps adversary-EMULATION tooling — Atomic Red Team and
MITRE Caldera — which in live mode fire *real* ATT&CK techniques. The single
most important control in the feature is therefore this: **an emulation may
only ever be aimed at an approved SANDBOX.** Any trigger whose ``target_env``
is not an approved sandbox is refused, fail-closed, before any emulator method
is reachable, and the refusal is written to the hash-chain audit ledger.

This module is the pure-policy half of that control (no DB, no I/O, no heavy
deps) so both the backend enforcement service
(:mod:`btagent_backend.services.detection_emulation_service`) and the agents-side
:class:`ValidationOrchestrator` import the *same* decision function. The backend
service turns a denial into an audited ledger row; the orchestrator re-asserts
the guard at its own entry (defence in depth) so no emulator dispatch path is
reachable without passing this check — even a direct, in-process caller.

Design notes
------------
* **Fail-closed.** Only :data:`APPROVED_SANDBOX_ENVS` is approved. An unknown,
  blank, or unrecognised ``target_env`` is denied, never waved through.
* **Allowlist, not denylist.** We enumerate what is *safe* (sandbox), not what
  is dangerous — a new environment name is denied by default until an operator
  adds it, rather than silently permitted.
* **Value-object result.** :func:`evaluate_sandbox_target` returns a
  :class:`SandboxDecision` (never raises for a business denial) so the caller
  owns the audit + response. :class:`SandboxViolationError` exists for the
  defence-in-depth call site (the orchestrator) that must hard-stop.
"""

from __future__ import annotations

from dataclasses import dataclass

from btagent_shared.types.detection_validation import TargetEnv

# --------------------------------------------------------------------------- #
# Approved sandboxes (the allowlist)
# --------------------------------------------------------------------------- #

# The ONLY target environments an emulation may run against. Kept as a frozenset
# of TargetEnv values so adding a future named sandbox is a one-line, reviewable
# change — and so anything not listed here is denied fail-closed.
APPROVED_SANDBOX_ENVS: frozenset[TargetEnv] = frozenset({TargetEnv.SANDBOX})


class SandboxViolationError(RuntimeError):
    """Raised at a defence-in-depth call site when a non-sandbox target reaches
    an emulator dispatch path. The backend enforcement service prefers the
    result-returning :func:`evaluate_sandbox_target` (so it can audit the
    denial before responding); the orchestrator raises this to guarantee no
    emulator method runs on a non-approved target."""

    def __init__(self, target_env: object) -> None:
        self.target_env = target_env
        super().__init__(
            f"Refusing adversary emulation: target_env={target_env!r} is not an "
            f"approved sandbox (approved: {sorted(e.value for e in APPROVED_SANDBOX_ENVS)})."
        )


@dataclass(frozen=True)
class SandboxDecision:
    """Outcome of a sandbox-target policy check.

    ``approved`` is the gate: only when it is True may a caller dispatch an
    emulator. ``reason`` is a human-readable, audit-safe explanation used both
    in the ledger ``details`` and in the API response on denial.
    """

    approved: bool
    target_env: str
    reason: str

    @property
    def denied(self) -> bool:
        return not self.approved


def _coerce(target_env: object) -> TargetEnv | None:
    """Best-effort coercion of an arbitrary input to a known TargetEnv.

    A value we cannot map to a known environment (typo, injected string, None)
    is treated as unknown → denied. We never raise here; an unparseable target
    is a *denial*, not a crash.
    """
    if isinstance(target_env, TargetEnv):
        return target_env
    if isinstance(target_env, str):
        try:
            return TargetEnv(target_env.strip().lower())
        except ValueError:
            return None
    return None


def is_approved_sandbox(target_env: object) -> bool:
    """True only when *target_env* resolves to an approved sandbox."""
    env = _coerce(target_env)
    return env is not None and env in APPROVED_SANDBOX_ENVS


def evaluate_sandbox_target(target_env: object) -> SandboxDecision:
    """Evaluate whether an emulation may run against *target_env*.

    Returns a :class:`SandboxDecision`; never raises for a business denial so
    the caller can record an audited denial before responding. The reason
    string is safe to persist in the audit ledger.
    """
    env = _coerce(target_env)
    raw = env.value if env is not None else (str(target_env) if target_env is not None else "")

    if env is None:
        return SandboxDecision(
            approved=False,
            target_env=raw,
            reason=(
                "target_env is unrecognised or blank — refusing emulation "
                "fail-closed; only an approved sandbox is permitted."
            ),
        )
    if env in APPROVED_SANDBOX_ENVS:
        return SandboxDecision(
            approved=True,
            target_env=env.value,
            reason=f"target_env={env.value} is an approved sandbox.",
        )
    return SandboxDecision(
        approved=False,
        target_env=env.value,
        reason=(
            f"target_env={env.value} is not an approved sandbox — adversary "
            f"emulation is refused outside {sorted(e.value for e in APPROVED_SANDBOX_ENVS)}."
        ),
    )


def require_sandbox(target_env: object) -> None:
    """Defence-in-depth hard-stop: raise :class:`SandboxViolationError` unless
    *target_env* is an approved sandbox. Called at emulator dispatch entry so
    no code path can fire a technique against a non-sandbox target."""
    if not is_approved_sandbox(target_env):
        raise SandboxViolationError(target_env)


__all__ = [
    "APPROVED_SANDBOX_ENVS",
    "SandboxDecision",
    "SandboxViolationError",
    "evaluate_sandbox_target",
    "is_approved_sandbox",
    "require_sandbox",
]
