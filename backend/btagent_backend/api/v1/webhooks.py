"""Webhook ingestion endpoints for external SIEM/EDR alert sources."""

from __future__ import annotations

import hmac
import logging
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import get_db
from btagent_backend.config import Settings, get_settings
from btagent_backend.db.models import InvestigationRow
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    # Splunk
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    # CrowdStrike numeric-style (detection.max_severity_displayname)
    "5": Severity.CRITICAL,
    "4": Severity.HIGH,
    "3": Severity.MEDIUM,
    "2": Severity.LOW,
    "1": Severity.INFO,
    # Sentinel
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


class WebhookAccepted(BaseModel):
    investigation_id: str
    status: str = "accepted"


class SplunkAlertPayload(BaseModel):
    """Splunk webhook alert payload."""

    search_name: str = ""
    app: str = ""
    owner: str = ""
    results_link: str = ""
    result: dict[str, Any] = Field(default_factory=dict)
    sid: str = ""
    severity: str = "medium"


class CrowdStrikeDetectionPayload(BaseModel):
    """CrowdStrike Falcon detection webhook payload."""

    detection_id: str = ""
    display_name: str = ""
    description: str = ""
    max_severity_displayname: str = "Medium"
    hostname: str = ""
    tactic: str = ""
    technique: str = ""
    device: dict[str, Any] = Field(default_factory=dict)
    behaviors: list[dict[str, Any]] = Field(default_factory=list)


class SentinelIncidentPayload(BaseModel):
    """Microsoft Sentinel incident webhook payload."""

    incident_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "Medium"
    status: str = ""
    classification: str = ""
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    entities: list[dict[str, Any]] = Field(default_factory=list)


class ElasticAlertPayload(BaseModel):
    """Elastic SIEM alert webhook payload."""

    rule_id: str = ""
    rule_name: str = ""
    alert_id: str = ""
    severity: str = "medium"
    description: str = ""
    source: dict[str, Any] = Field(default_factory=dict)
    kibana_url: str = ""
    hits: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw, _SEVERITY_MAP.get(raw.lower(), Severity.MEDIUM)).value


def _verify_secret(
    provided: str | None,
    settings: Settings,
    source: str,
) -> None:
    expected = getattr(settings, "webhook_secret", None) or settings.jwt_secret
    if not provided or not hmac.compare_digest(provided, expected):
        logger.warning("Webhook secret mismatch from source=%s", source)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing webhook secret",
        )


async def _create_investigation(
    db: AsyncSession,
    *,
    title: str,
    description: str,
    severity: str,
    source: str,
    raw_payload: dict[str, Any],
) -> InvestigationRow:
    inv = InvestigationRow(
        id=generate_id("inv"),
        title=title,
        description=description,
        severity=severity,
        status=InvestigationStatus.PENDING.value,
        config={"webhook_source": source, "raw_alert": raw_payload},
    )
    db.add(inv)
    await db.flush()
    logger.info(
        "Webhook investigation created: id=%s source=%s severity=%s",
        inv.id,
        source,
        severity,
    )
    return inv


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/splunk", response_model=WebhookAccepted, status_code=202)
async def ingest_splunk(
    body: SplunkAlertPayload,
    request: Request,
    x_webhook_secret: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Receive a Splunk alert webhook and create a pending investigation."""
    _verify_secret(x_webhook_secret, settings, "splunk")

    severity = _normalize_severity(body.severity)
    title = f"[Splunk] {body.search_name}" if body.search_name else "[Splunk] Alert"
    description_parts = [
        f"Splunk search: {body.search_name}",
        f"App: {body.app}",
        f"Results: {body.results_link}",
    ]
    if body.result:
        description_parts.append(f"Top result keys: {', '.join(list(body.result.keys())[:10])}")

    inv = await _create_investigation(
        db,
        title=title,
        description="\n".join(description_parts),
        severity=severity,
        source="splunk",
        raw_payload=body.model_dump(),
    )
    return WebhookAccepted(investigation_id=inv.id)


@router.post("/crowdstrike", response_model=WebhookAccepted, status_code=202)
async def ingest_crowdstrike(
    body: CrowdStrikeDetectionPayload,
    request: Request,
    x_webhook_secret: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Receive a CrowdStrike Falcon detection webhook and create a pending investigation."""
    _verify_secret(x_webhook_secret, settings, "crowdstrike")

    severity = _normalize_severity(body.max_severity_displayname)
    title = (
        f"[CrowdStrike] {body.display_name}"
        if body.display_name
        else "[CrowdStrike] Detection"
    )
    description_parts = [
        f"Detection: {body.detection_id}",
        f"Host: {body.hostname}",
    ]
    if body.tactic:
        description_parts.append(f"MITRE Tactic: {body.tactic}")
    if body.technique:
        description_parts.append(f"MITRE Technique: {body.technique}")
    if body.description:
        description_parts.append(f"Details: {body.description}")

    inv = await _create_investigation(
        db,
        title=title,
        description="\n".join(description_parts),
        severity=severity,
        source="crowdstrike",
        raw_payload=body.model_dump(),
    )
    return WebhookAccepted(investigation_id=inv.id)


@router.post("/sentinel", response_model=WebhookAccepted, status_code=202)
async def ingest_sentinel(
    body: SentinelIncidentPayload,
    request: Request,
    x_webhook_secret: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Receive a Microsoft Sentinel incident webhook and create a pending investigation."""
    _verify_secret(x_webhook_secret, settings, "sentinel")

    severity = _normalize_severity(body.severity)
    title = f"[Sentinel] {body.title}" if body.title else "[Sentinel] Incident"
    description_parts = [
        f"Sentinel incident: {body.incident_id}",
    ]
    if body.description:
        description_parts.append(f"Description: {body.description}")
    if body.classification:
        description_parts.append(f"Classification: {body.classification}")
    if body.alerts:
        description_parts.append(f"Alert count: {len(body.alerts)}")
    if body.entities:
        description_parts.append(f"Entity count: {len(body.entities)}")

    inv = await _create_investigation(
        db,
        title=title,
        description="\n".join(description_parts),
        severity=severity,
        source="sentinel",
        raw_payload=body.model_dump(),
    )
    return WebhookAccepted(investigation_id=inv.id)


@router.post("/elastic", response_model=WebhookAccepted, status_code=202)
async def ingest_elastic(
    body: ElasticAlertPayload,
    request: Request,
    x_webhook_secret: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Receive an Elastic SIEM alert webhook and create a pending investigation."""
    _verify_secret(x_webhook_secret, settings, "elastic")

    severity = _normalize_severity(body.severity)
    title = f"[Elastic] {body.rule_name}" if body.rule_name else "[Elastic] Alert"
    description_parts = [
        f"Rule: {body.rule_name} ({body.rule_id})",
        f"Alert ID: {body.alert_id}",
    ]
    if body.description:
        description_parts.append(f"Description: {body.description}")
    if body.kibana_url:
        description_parts.append(f"Kibana: {body.kibana_url}")
    if body.hits:
        description_parts.append(f"Hit count: {len(body.hits)}")

    inv = await _create_investigation(
        db,
        title=title,
        description="\n".join(description_parts),
        severity=severity,
        source="elastic",
        raw_payload=body.model_dump(),
    )
    return WebhookAccepted(investigation_id=inv.id)
