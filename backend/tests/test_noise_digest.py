"""Tests for the newly-noisy digest (#112 closing loop).

``run_noise_digest`` diffs the current noise baseline against the per-org
``noise_digest_state`` memory: additions notify hunt seniors once, repeats
stay silent, and a rule that leaves the baseline and returns re-notifies.

Shared-org caution: pack-run rows and notifications accumulate across the
test session, so assertions scope by per-test unique pack/rule ids carried
in the notification message — never absolute counts. Because other tests'
pack runs are also part of the org baseline, the FIRST digest in this file
absorbs any pre-existing noisy rules into the state (cold-start catch-up);
subsequent assertions diff against that.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from btagent_shared.utils.ids import generate_id
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID, NotificationRow
from btagent_backend.db.models_hunt import HuntPackRunRow, NoiseDigestStateRow
from btagent_backend.services.noise_digest import run_noise_digest

_T0 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)


async def _seed_noisy_rule(db_session, pack_id: str, rule_id: str, title: str) -> None:
    """Three completed runs where the rule always hits — chronically noisy."""
    for day in range(3):
        db_session.add(
            HuntPackRunRow(
                id=generate_id("hpr"),
                org_id=DEFAULT_ORG_ID,
                run_id=generate_id("hrun"),
                pack_id=pack_id,
                pack_name="Digest pack",
                backends=["splunk"],
                rule_stats={rule_id: {"title": title, "hits": 5, "errors": 0}},
                hit_count=5,
                error_count=0,
                findings_created=0,
                status="completed",
                started_at=_T0 + timedelta(days=day),
            )
        )
    await db_session.flush()


async def _digest_notifications(db_session, user_id: str, marker: str) -> list[NotificationRow]:
    result = await db_session.execute(
        select(NotificationRow).where(
            NotificationRow.user_id == user_id,
            NotificationRow.type == "noise_digest",
        )
    )
    return [r for r in result.scalars().all() if marker in r.message]


async def test_digest_notifies_new_rule_once_then_stays_silent(db_session, sample_user, admin_user):
    # Absorb whatever is already noisy in the shared org (cold start).
    await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)

    marker = f"Chronic beacon {generate_id('mk')}"
    await _seed_noisy_rule(db_session, generate_id("pack"), generate_id("rule"), marker)

    first = await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)
    assert first["new"] >= 1
    admin_rows = await _digest_notifications(db_session, admin_user.id, marker)
    assert len(admin_rows) == 1
    assert admin_rows[0].title == "Newly Noisy Rules"
    assert admin_rows[0].link == "/hunt"
    # Analysts don't hold hunt:promote — no digest for them.
    assert await _digest_notifications(db_session, sample_user.id, marker) == []

    # Second sweep with no change: the same rule must not re-notify.
    await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)
    assert len(await _digest_notifications(db_session, admin_user.id, marker)) == 1


async def test_rule_that_returns_after_going_quiet_renotifies(db_session, admin_user):
    await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)

    marker = f"Regression beacon {generate_id('mk')}"
    pack_id, rule_id = generate_id("pack"), generate_id("rule")
    await _seed_noisy_rule(db_session, pack_id, rule_id, marker)
    await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)
    assert len(await _digest_notifications(db_session, admin_user.id, marker)) == 1

    # Simulate the rule going quiet: drop its key from the stored state (as a
    # sweep over a baseline without it would). The next sweep sees it as NEW
    # again and re-notifies — a regression is signal, not a repeat.
    state = await db_session.get(NoiseDigestStateRow, DEFAULT_ORG_ID)
    assert state is not None
    key = f"{pack_id}:{rule_id}"
    assert key in state.noisy_keys
    state.noisy_keys = [k for k in state.noisy_keys if k != key]
    await db_session.flush()

    await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)
    assert len(await _digest_notifications(db_session, admin_user.id, marker)) == 2


async def test_state_row_tracks_current_baseline_keys(db_session, admin_user):
    marker = f"State-tracked {generate_id('mk')}"
    pack_id, rule_id = generate_id("pack"), generate_id("rule")
    await _seed_noisy_rule(db_session, pack_id, rule_id, marker)
    await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)

    state = await db_session.get(NoiseDigestStateRow, DEFAULT_ORG_ID)
    assert state is not None
    assert f"{pack_id}:{rule_id}" in state.noisy_keys


async def test_digest_summary_counts_multiple_new_rules(db_session, admin_user):
    await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)

    marker = f"Batch {generate_id('mk')}"
    pack_id = generate_id("pack")
    await _seed_noisy_rule(db_session, pack_id, generate_id("rule"), f"{marker} one")
    await _seed_noisy_rule(db_session, pack_id, generate_id("rule"), f"{marker} two")

    result = await run_noise_digest(db_session, org_id=DEFAULT_ORG_ID, lookback_runs=500)
    assert result["new"] >= 2
    # One digest notification per recipient — not one per rule.
    rows = await _digest_notifications(db_session, admin_user.id, marker)
    assert len(rows) == 1
    assert "more" in rows[0].message or "rules turned chronically noisy" in rows[0].message
