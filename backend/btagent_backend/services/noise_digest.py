"""Newly-noisy digest — scheduled diff of the noise baseline (#112).

Closes the last loop on the noise baseline: instead of an analyst having to
open the triage page to discover that a rule turned chronically noisy, the
scheduled sweep diffs the current baseline against the per-org
:class:`NoiseDigestStateRow` memory and notifies hunt seniors about the
NEW entries only (in-app, deep-linked to the Noisy Rules panel where the
one-click suppression lives).

Diff semantics:

* Keys are ``"pack_id:rule_id"`` — same identity the baseline reports.
* Only additions notify. Rules that stay noisy are silent (the panel
  still shows them); rules that go quiet are dropped from the stored set,
  so a later regression re-notifies — regressions are signal, not repeats.
* Cold start (no state row) treats everything currently noisy as new:
  the first digest after enabling the sweep is a full catch-up, once.

Flushes but never commits — the arq job wrapper owns the commit.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import Settings
from btagent_backend.db.models_hunt import NoiseDigestStateRow
from btagent_backend.services.hunt_notifier import notify_newly_noisy_rules
from btagent_backend.services.noise_baseline import noise_baseline

logger = logging.getLogger("btagent.services.noise_digest")


def _key(rule: Any) -> str:
    return f"{rule.pack_id}:{rule.rule_id}"


async def run_noise_digest(
    db: AsyncSession,
    *,
    org_id: str,
    lookback_runs: int = 50,
    min_runs: int = 3,
    hit_rate_threshold: float = 0.8,
    redis: Any | None = None,
    settings: Settings | None = None,
) -> dict[str, int]:
    """Diff the org's noise baseline against stored state; notify on additions.

    Returns counters for the job result: ``noisy`` (current baseline size),
    ``new`` (rules that notified), ``notified`` (notification rows created).
    """
    baseline = await noise_baseline(
        db,
        org_id=org_id,
        lookback_runs=lookback_runs,
        min_runs=min_runs,
        hit_rate_threshold=hit_rate_threshold,
    )
    current_keys = sorted({_key(r) for r in baseline.items})

    state = await db.get(NoiseDigestStateRow, org_id)
    previous = set(state.noisy_keys or []) if state is not None else set()
    new_key_set = set(current_keys) - previous
    new_rules = [r for r in baseline.items if _key(r) in new_key_set]

    notified = await notify_newly_noisy_rules(
        db, org_id=org_id, rules=new_rules, redis=redis, settings=settings
    )

    if state is None:
        db.add(NoiseDigestStateRow(org_id=org_id, noisy_keys=current_keys))
    else:
        state.noisy_keys = current_keys
    await db.flush()

    logger.info(
        "noise digest (org=%s): noisy=%d new=%d notified=%d",
        org_id,
        len(current_keys),
        len(new_rules),
        len(notified),
    )
    return {"noisy": len(current_keys), "new": len(new_rules), "notified": len(notified)}
