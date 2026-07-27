"""Cloud control-plane hunt run service — detectors → findings → triage inbox (#117).

The backend side-effectful shell for the cloud control-plane vertical, mirroring
:mod:`agentic_hunt_run_service`. It runs the cloud hunt (slice 1's
``run_cloud_hunt_mock``) and **persists** the resulting findings into the #119
hunt-findings store via :func:`hunt_triage_service.persist_hunt_findings` — so
cloud control-plane findings (cross-account trust abuse, shadow workloads,
overprivileged identities, and — on the live path — STS chaining, IAM
persistence, snapshot share, CloudTrail tamper) land in the same Hunt Triage
inbox as the other verticals.

Unlike the connector-backed verticals, the cloud domain has **no live
control-plane connector yet** (CloudTrail / IAM / resource-event ingest is
deferred to #100), so the hunt runs over the runner's deterministic demo bundle.
The persistence helper never commits — the caller (an API route) owns the
commit. Mock-first: the demo bundle is synthetic, so this is safe to run in CI.

Phase-C closed loop (#113, mirroring ``hunt_plan_service._file_clean_ttp_proposals``):
a cloud-hunt-covered technique that produced **no** finding this run is CLEAN
coverage — the natural next step is a detection rule so the technique alerts
without a hunt. Those clean TTPs are filed as draft detection proposals in the
#113 review queue via :func:`cti_detection_service.persist_proposals`.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.services.cloud_hunt_run")


async def run_cloud_hunt_and_ingest(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
) -> dict[str, Any]:
    """Run a cloud control-plane hunt and land its findings in the triage inbox.

    Runs the connector-independent detectors over the runner's demo bundle, maps
    their output into ``cloud``-domain findings, and persists them (clustered +
    suppression-checked on insert). Not committed — the caller commits once.

    Returns a summary: the observation-bundle size, findings emitted vs. actually
    created (suppressions drop the delta), the severity breakdown, and the number
    of clean-TTP detection proposals filed to #113.
    """
    from btagent_agents.plugins.triage.cloud_hunt import run_cloud_hunt_mock

    result = run_cloud_hunt_mock()

    rows = await hunt_triage_service.persist_hunt_findings(
        db, org_id=org_id, findings=result.findings
    )

    # #113 Phase-C closed loop: covered techniques with zero findings this run
    # become draft detection proposals. Best-effort — a proposal-filing failure
    # must never sink the ingest that already landed findings.
    clean_proposals = 0
    try:
        clean_proposals = await _file_clean_cloud_ttp_proposals(db, org_id=org_id, result=result)
    except Exception:  # noqa: BLE001 — proposal filing is auxiliary
        logger.warning(
            "clean-TTP proposal filing failed for cloud hunt (org=%s)", org_id, exc_info=True
        )

    summary = {
        "org_id": org_id,
        "total_identities": result.total_identities,
        "total_workloads": result.total_workloads,
        "total_cloudtrail_events": result.total_cloudtrail_events,
        "total_resource_events": result.total_resource_events,
        "findings_emitted": len(result.findings),
        "findings_created": len(rows),
        "counts_by_severity": result.counts_by_severity,
        "clean_ttp_proposals": clean_proposals,
    }
    logger.info("cloud_hunt_and_ingest org=%s: %s", org_id, summary)
    return summary


async def _file_clean_cloud_ttp_proposals(
    db: AsyncSession,
    *,
    org_id: str,
    result: Any,
) -> int:
    """File draft #113 detection proposals for cleanly-hunted cloud TTPs (#117 Phase C).

    Mirrors ``hunt_plan_service._file_clean_ttp_proposals``: a technique the cloud
    hunt *covers* (``CLOUD_HUNT_COVERED_TECHNIQUES``) but for which this run
    produced **no** finding is verified-clean coverage — file a draft Sigma rule
    so it alerts without a hunt next time. Proposals land ``proposed`` via
    :func:`persist_proposals`, keyed on a deterministic
    ``cloud-hunt--{ttp_id}`` source id so re-runs upsert (never duplicating) and
    analyst-decided rows are never overwritten.

    Returns the number of proposals passed to the upsert (created + refreshed).
    """
    from btagent_shared.hunt.cloud import CLOUD_HUNT_COVERED_TECHNIQUES
    from btagent_shared.types.detection_proposal import DetectionProposal

    from btagent_backend.services.cti_detection_service import persist_proposals

    fired: set[str] = set()
    for finding in result.findings:
        fired.update(finding.technique_ids)

    now = datetime.now(UTC)
    proposals: list[DetectionProposal] = []
    for ttp_id, name in CLOUD_HUNT_COVERED_TECHNIQUES.items():
        if ttp_id in fired:
            continue  # technique fired this run — not clean
        tag = ttp_id.lower().replace(".", "_") if "." in ttp_id else ttp_id.lower()
        # attack.tXXXX or attack.tXXXX.YYY — Sigma tag form uses dotted subtech.
        attack_tag = f"attack.{ttp_id.lower()}"
        sigma_yaml = (
            f"title: {name} ({ttp_id}) — draft from clean cloud hunt\n"
            "status: experimental\n"
            "description: >-\n"
            f"  Cloud control-plane hunt exercised {ttp_id} ({name}) and found no\n"
            "  matching activity (clean coverage). Draft rule so the technique alerts\n"
            "  without requiring a hunt. Translate the code detector into a Sigma\n"
            "  selection before accepting.\n"
            f"references:\n  - https://attack.mitre.org/techniques/{ttp_id.replace('.', '/')}/\n"
            f"tags:\n  - {attack_tag}\n  - cloud.control-plane\n"
            "logsource:\n  product: aws\n  service: cloudtrail\n"
            "detection:\n"
            "  selection:\n"
            "    # TODO(detection-engineering): translate the cloud control-plane\n"
            "    # detector into a Sigma selection before accepting.\n"
            "    eventName: PLACEHOLDER\n"
            "  condition: selection\n"
            "level: medium\n"
        )
        proposals.append(
            DetectionProposal(
                id=f"dprop-cloud-hunt-{tag}",
                source_stix_id=f"cloud-hunt--{ttp_id}",
                title=f"Detection gap: {ttp_id} — {name} (clean cloud hunt)",
                sigma_yaml=sigma_yaml,
                technique_ids=[ttp_id],
                confidence=0.3,
                rationale=(
                    f"The connector-independent cloud control-plane hunt exercised {ttp_id} "
                    f"({name}) and produced no finding (clean coverage). Filing a draft rule "
                    "so the technique alerts without requiring a hunt."
                ),
                generated_at=now,
            )
        )

    if not proposals:
        return 0
    created, updated, unchanged = await persist_proposals(db, org_id=org_id, proposals=proposals)
    logger.info(
        "cloud-hunt clean-TTP proposals (org=%s): created=%d updated=%d unchanged=%d",
        org_id,
        created,
        updated,
        unchanged,
    )
    return len(proposals)
