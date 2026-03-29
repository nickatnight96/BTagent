"""MITRE ATT&CK service — matrix loading, tagging, coverage analysis, and export.

Provides the business logic layer for all MITRE ATT&CK operations including
loading the STIX bundle, tagging entities with techniques, calculating coverage
maps and detection gaps, and exporting ATT&CK Navigator layers.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from btagent_shared.types.mitre import (
    CoverageMap,
    DetectionGap,
    MitreGroup,
    MitreTactic,
    MitreTechnique,
    NavigatorLayer,
    NavigatorTechnique,
    TechniqueCoverage,
)
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_mitre import (
    MitreGroupRow,
    MitreTacticRow,
    MitreTechniqueRow,
    MitreTechniqueTagRow,
)

logger = logging.getLogger("btagent.services.mitre")

# Kill-chain phase shortname -> ordinal mapping (Enterprise ATT&CK)
_TACTIC_ORDINALS: dict[str, int] = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}

# Navigator score colour thresholds
_SCORE_COLORS = {
    0: "#ffffff",
    1: "#c6dbef",
    5: "#6baed6",
    10: "#2171b5",
    25: "#08306b",
}


# ---------------------------------------------------------------------------
# STIX 2.1 Bundle Parsing
# ---------------------------------------------------------------------------


def _extract_external_id(obj: dict[str, Any]) -> str | None:
    """Extract the MITRE ID (e.g. T1059) from STIX external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_url(obj: dict[str, Any]) -> str:
    """Extract the ATT&CK URL from STIX external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _extract_kill_chain_phase(obj: dict[str, Any]) -> str:
    """Extract the primary tactic shortname from STIX kill_chain_phases."""
    phases = obj.get("kill_chain_phases", [])
    for phase in phases:
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name", "")
    return ""


def _parse_techniques(objects: list[dict]) -> list[dict[str, Any]]:
    """Parse attack-pattern objects into technique dicts."""
    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        ext_id = _extract_external_id(obj)
        if not ext_id:
            continue

        tactic = _extract_kill_chain_phase(obj)
        if not tactic:
            continue

        techniques.append(
            {
                "id": ext_id,
                "name": obj.get("name", ""),
                "tactic": tactic,
                "description": obj.get("description", ""),
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "detection": obj.get("x_mitre_detection", ""),
                "url": _extract_url(obj),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
        )
    return techniques


def _parse_tactics(objects: list[dict]) -> list[dict[str, Any]]:
    """Parse x-mitre-tactic objects into tactic dicts."""
    tactics = []
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if obj.get("revoked", False):
            continue

        ext_id = _extract_external_id(obj)
        if not ext_id:
            continue

        shortname = obj.get("x_mitre_shortname", "")
        ordinal = _TACTIC_ORDINALS.get(shortname, 99)

        tactics.append(
            {
                "id": ext_id,
                "name": obj.get("name", ""),
                "shortname": shortname,
                "description": obj.get("description", ""),
                "ordinal": ordinal,
            }
        )
    return tactics


def _parse_groups(
    objects: list[dict], relationship_map: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Parse intrusion-set objects into group dicts with technique associations."""
    groups = []
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked", False):
            continue

        ext_id = _extract_external_id(obj)
        if not ext_id:
            continue

        stix_id = obj.get("id", "")
        technique_ids = relationship_map.get(stix_id, [])

        groups.append(
            {
                "id": ext_id,
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "description": obj.get("description", ""),
                "technique_ids": technique_ids,
            }
        )
    return groups


def _build_relationship_map(objects: list[dict]) -> dict[str, list[str]]:
    """Build a map of source STIX ID -> list of target MITRE technique IDs.

    Scans relationship objects of type 'uses' where the target is an
    attack-pattern. Returns mapping keyed by the source_ref (e.g. an
    intrusion-set STIX ID) with values being lists of MITRE technique IDs.
    """
    # First build STIX ID -> MITRE external ID index for attack-patterns
    stix_to_mitre: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            ext_id = _extract_external_id(obj)
            if ext_id:
                stix_to_mitre[obj["id"]] = ext_id

    # Now walk relationships
    rel_map: dict[str, list[str]] = defaultdict(list)
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked", False):
            continue

        target_ref = obj.get("target_ref", "")
        mitre_id = stix_to_mitre.get(target_ref)
        if mitre_id:
            source_ref = obj.get("source_ref", "")
            rel_map[source_ref].append(mitre_id)

    return dict(rel_map)


# ---------------------------------------------------------------------------
# Service class
# ---------------------------------------------------------------------------


class MitreService:
    """MITRE ATT&CK data operations."""

    # ------------------------------------------------------------------
    # Matrix loading
    # ------------------------------------------------------------------

    @staticmethod
    async def load_attack_matrix(
        db: AsyncSession,
        stix_bundle_path: str | Path,
    ) -> dict[str, int]:
        """Parse a STIX 2.1 JSON bundle and upsert techniques/tactics/groups.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        stix_bundle_path : str | Path
            Filesystem path to the STIX bundle JSON file.

        Returns
        -------
        dict[str, int]
            Counts of upserted objects: {"techniques", "tactics", "groups"}.
        """
        path = Path(stix_bundle_path)
        if not path.exists():
            raise FileNotFoundError(f"STIX bundle not found: {path}")

        with open(path) as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        if not objects:
            logger.warning("STIX bundle at %s contains no objects", path)
            return {"techniques": 0, "tactics": 0, "groups": 0}

        relationship_map = _build_relationship_map(objects)

        techniques = _parse_techniques(objects)
        tactics = _parse_tactics(objects)
        groups = _parse_groups(objects, relationship_map)

        # Upsert tactics
        for t in tactics:
            stmt = pg_insert(MitreTacticRow).values(**t)
            stmt = stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "name": stmt.excluded.name,
                    "shortname": stmt.excluded.shortname,
                    "description": stmt.excluded.description,
                    "ordinal": stmt.excluded.ordinal,
                },
            )
            await db.execute(stmt)

        # Upsert techniques
        for t in techniques:
            stmt = pg_insert(MitreTechniqueRow).values(**t)
            stmt = stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "name": stmt.excluded.name,
                    "tactic": stmt.excluded.tactic,
                    "description": stmt.excluded.description,
                    "platforms": stmt.excluded.platforms,
                    "data_sources": stmt.excluded.data_sources,
                    "detection": stmt.excluded.detection,
                    "url": stmt.excluded.url,
                    "is_subtechnique": stmt.excluded.is_subtechnique,
                },
            )
            await db.execute(stmt)

        # Upsert groups
        for g in groups:
            stmt = pg_insert(MitreGroupRow).values(**g)
            stmt = stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "name": stmt.excluded.name,
                    "aliases": stmt.excluded.aliases,
                    "description": stmt.excluded.description,
                    "technique_ids": stmt.excluded.technique_ids,
                },
            )
            await db.execute(stmt)

        await db.flush()

        counts = {
            "techniques": len(techniques),
            "tactics": len(tactics),
            "groups": len(groups),
        }
        logger.info(
            "MITRE ATT&CK matrix loaded: %d techniques, %d tactics, %d groups",
            counts["techniques"],
            counts["tactics"],
            counts["groups"],
        )
        return counts

    # ------------------------------------------------------------------
    # Tagging
    # ------------------------------------------------------------------

    @staticmethod
    async def tag_technique(
        db: AsyncSession,
        *,
        entity_type: str,
        entity_id: str,
        technique_id: str,
        confidence: float = 0.5,
        tagged_by: str = "",
    ) -> MitreTechniqueTagRow:
        """Create a tag associating a technique with an entity.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        entity_type : str
            Kind of entity (ioc, timeline, alert, etc.).
        entity_id : str
            Entity primary key.
        technique_id : str
            MITRE technique ID (e.g. T1059.001).
        confidence : float
            Confidence score (0.0-1.0).
        tagged_by : str
            User ID or agent name that created the tag.

        Returns
        -------
        MitreTechniqueTagRow
            The newly created tag row.
        """
        row = MitreTechniqueTagRow(
            id=generate_id("mt"),
            entity_type=entity_type,
            entity_id=entity_id,
            technique_id=technique_id,
            confidence=confidence,
            tagged_by=tagged_by,
        )
        db.add(row)
        await db.flush()

        logger.info(
            "Tagged %s/%s with technique %s (confidence=%.2f, by=%s)",
            entity_type,
            entity_id,
            technique_id,
            confidence,
            tagged_by,
        )
        return row

    # ------------------------------------------------------------------
    # Coverage analysis
    # ------------------------------------------------------------------

    @staticmethod
    async def get_coverage(
        db: AsyncSession,
        investigation_id: str | None = None,
    ) -> CoverageMap:
        """Return a CoverageMap grouped by tactic.

        Optionally filtered to tags associated with a specific investigation's
        entities (matched by entity_id prefix or a join through IOC/timeline).

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        investigation_id : str | None
            If provided, only count tags for entities belonging to this
            investigation.

        Returns
        -------
        CoverageMap
        """
        # Build the query for tag counts per technique
        tag_query = select(
            MitreTechniqueTagRow.technique_id,
            func.count(MitreTechniqueTagRow.id).label("cnt"),
        ).group_by(MitreTechniqueTagRow.technique_id)

        if investigation_id:
            # Filter tags whose entity_id belongs to the investigation.
            # Convention: entity_ids contain investigation context or we join.
            # Use a subquery approach: find entity_ids from iocs + timeline_entries
            from btagent_backend.db.models import IOCRow, TimelineEntryRow

            ioc_ids = select(IOCRow.id).where(IOCRow.investigation_id == investigation_id)
            timeline_ids = select(TimelineEntryRow.id).where(
                TimelineEntryRow.investigation_id == investigation_id
            )
            tag_query = tag_query.where(
                or_(
                    MitreTechniqueTagRow.entity_id.in_(ioc_ids),
                    MitreTechniqueTagRow.entity_id.in_(timeline_ids),
                )
            )

        result = await db.execute(tag_query)
        tag_counts: dict[str, int] = {}
        for tech_id, cnt in result.all():
            tag_counts[tech_id] = cnt

        # Fetch all techniques grouped by tactic
        tech_result = await db.execute(
            select(MitreTechniqueRow).order_by(MitreTechniqueRow.tactic, MitreTechniqueRow.id)
        )
        all_techniques = tech_result.scalars().all()

        tactics_map: dict[str, list[TechniqueCoverage]] = defaultdict(list)
        total_techniques = 0
        covered_techniques = 0

        for tech in all_techniques:
            total_techniques += 1
            count = tag_counts.get(tech.id, 0)
            if count > 0:
                covered_techniques += 1
            tactics_map[tech.tactic].append(
                TechniqueCoverage(
                    technique_id=tech.id,
                    technique_name=tech.name,
                    count=count,
                )
            )

        return CoverageMap(
            tactics=dict(tactics_map),
            total_techniques=total_techniques,
            covered_techniques=covered_techniques,
        )

    @staticmethod
    async def get_coverage_score(
        db: AsyncSession,
        investigation_id: str | None = None,
    ) -> float:
        """Return the percentage of techniques with at least one detection/tag.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        investigation_id : str | None
            Optional investigation scope filter.

        Returns
        -------
        float
            Percentage (0.0-100.0) of techniques covered.
        """
        coverage = await MitreService.get_coverage(db, investigation_id)
        if coverage.total_techniques == 0:
            return 0.0
        return round((coverage.covered_techniques / coverage.total_techniques) * 100, 2)

    @staticmethod
    async def get_detection_gaps(
        db: AsyncSession,
        investigation_id: str | None = None,
    ) -> list[DetectionGap]:
        """Identify techniques without detection data per tactic.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        investigation_id : str | None
            Optional investigation scope filter.

        Returns
        -------
        list[DetectionGap]
        """
        coverage = await MitreService.get_coverage(db, investigation_id)
        gaps: list[DetectionGap] = []

        for tactic, techniques in coverage.tactics.items():
            uncovered = [t.technique_id for t in techniques if t.count == 0]
            if not uncovered:
                continue

            # Gather missing data sources for uncovered techniques
            if uncovered:
                ds_result = await db.execute(
                    select(MitreTechniqueRow.data_sources).where(
                        MitreTechniqueRow.id.in_(uncovered)
                    )
                )
                all_ds: set[str] = set()
                for row in ds_result.scalars().all():
                    if isinstance(row, list):
                        all_ds.update(row)

                gaps.append(
                    DetectionGap(
                        tactic=tactic,
                        techniques_without_detection=uncovered,
                        data_sources_missing=sorted(all_ds),
                    )
                )

        return gaps

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    @staticmethod
    async def search_techniques(
        db: AsyncSession,
        query: str,
        *,
        tactic_filter: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MitreTechnique]:
        """Full-text search over technique name and description.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        query : str
            Search term (case-insensitive ILIKE).
        tactic_filter : str | None
            Restrict results to a specific tactic shortname.
        limit : int
            Max results.
        offset : int
            Pagination offset.

        Returns
        -------
        list[MitreTechnique]
        """
        pattern = f"%{query}%"
        stmt = select(MitreTechniqueRow).where(
            or_(
                MitreTechniqueRow.name.ilike(pattern),
                MitreTechniqueRow.description.ilike(pattern),
                MitreTechniqueRow.id.ilike(pattern),
            )
        )

        if tactic_filter:
            stmt = stmt.where(MitreTechniqueRow.tactic == tactic_filter)

        stmt = stmt.order_by(MitreTechniqueRow.id).offset(offset).limit(limit)
        result = await db.execute(stmt)
        rows = result.scalars().all()

        return [_row_to_technique(r) for r in rows]

    @staticmethod
    async def search_ttps_for_environment(
        db: AsyncSession,
        org_profile: dict[str, Any],
    ) -> list[MitreTechnique]:
        """Suggest techniques relevant to the organisation's tech stack.

        Examines the org profile's platforms, cloud providers, and technologies
        to filter the ATT&CK matrix to relevant techniques.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        org_profile : dict[str, Any]
            Organisation profile dict (as stored in org_config).

        Returns
        -------
        list[MitreTechnique]
        """
        tech_stack = org_profile.get("tech_stack", {})

        # Collect platform keywords from the org profile
        platform_keywords: list[str] = []

        os_types = tech_stack.get("operating_systems", [])
        if isinstance(os_types, list):
            platform_keywords.extend(os_types)

        cloud_providers = tech_stack.get("cloud_providers", [])
        if isinstance(cloud_providers, list):
            for cp in cloud_providers:
                if "aws" in str(cp).lower():
                    platform_keywords.append("AWS")
                elif "azure" in str(cp).lower():
                    platform_keywords.append("Azure AD")
                elif "gcp" in str(cp).lower() or "google" in str(cp).lower():
                    platform_keywords.append("Google Workspace")

        # Also check for container/SaaS/IaaS keywords
        infra = tech_stack.get("infrastructure", [])
        if isinstance(infra, list):
            for item in infra:
                item_lower = str(item).lower()
                if "container" in item_lower or "docker" in item_lower:
                    platform_keywords.append("Containers")
                if "kubernetes" in item_lower:
                    platform_keywords.append("Containers")

        if not platform_keywords:
            # Default to common enterprise platforms
            platform_keywords = ["Windows", "Linux", "macOS"]

        # Query techniques whose platforms overlap with org profile
        # JSONB array overlap: platform column ? any of the keywords
        conditions = []
        for kw in platform_keywords:
            conditions.append(MitreTechniqueRow.platforms.op("@>")(json.dumps([kw])))

        if not conditions:
            return []

        stmt = (
            select(MitreTechniqueRow)
            .where(or_(*conditions))
            .order_by(MitreTechniqueRow.tactic, MitreTechniqueRow.id)
            .limit(200)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()

        return [_row_to_technique(r) for r in rows]

    # ------------------------------------------------------------------
    # Threat groups
    # ------------------------------------------------------------------

    @staticmethod
    async def get_threat_groups(
        db: AsyncSession,
        technique_id: str | None = None,
    ) -> list[MitreGroup]:
        """List threat groups, optionally filtered by a technique.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        technique_id : str | None
            If provided, only return groups that use this technique.

        Returns
        -------
        list[MitreGroup]
        """
        stmt = select(MitreGroupRow).order_by(MitreGroupRow.name)

        if technique_id:
            # JSONB array contains check
            stmt = stmt.where(MitreGroupRow.technique_ids.op("@>")(json.dumps([technique_id])))

        result = await db.execute(stmt)
        rows = result.scalars().all()

        return [
            MitreGroup(
                id=r.id,
                name=r.name,
                aliases=r.aliases or [],
                description=r.description or "",
                techniques=r.technique_ids or [],
            )
            for r in rows
        ]

    @staticmethod
    async def get_group_by_id(
        db: AsyncSession,
        group_id: str,
    ) -> MitreGroup | None:
        """Fetch a single threat group by ID.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        group_id : str
            Group ID (e.g. G0007).

        Returns
        -------
        MitreGroup | None
        """
        result = await db.execute(select(MitreGroupRow).where(MitreGroupRow.id == group_id))
        row = result.scalar_one_or_none()
        if not row:
            return None

        return MitreGroup(
            id=row.id,
            name=row.name,
            aliases=row.aliases or [],
            description=row.description or "",
            techniques=row.technique_ids or [],
        )

    # ------------------------------------------------------------------
    # Navigator export
    # ------------------------------------------------------------------

    @staticmethod
    async def export_navigator_layer(
        db: AsyncSession,
        investigation_id: str | None = None,
    ) -> NavigatorLayer:
        """Export an ATT&CK Navigator compatible JSON layer.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        investigation_id : str | None
            If provided, layer reflects coverage for this investigation only.

        Returns
        -------
        NavigatorLayer
        """
        coverage = await MitreService.get_coverage(db, investigation_id)

        nav_techniques: list[NavigatorTechnique] = []
        for tactic, techniques in coverage.tactics.items():
            for tech in techniques:
                score = min(tech.count, 100)
                color = ""
                for threshold in sorted(_SCORE_COLORS.keys(), reverse=True):
                    if score >= threshold:
                        color = _SCORE_COLORS[threshold]
                        break

                nav_techniques.append(
                    NavigatorTechnique(
                        techniqueID=tech.technique_id,
                        tactic=tactic,
                        score=score,
                        color=color if score > 0 else "",
                        comment=(f"Detected {tech.count} time(s)" if tech.count > 0 else ""),
                        enabled=True,
                        showSubtechniques="." in tech.technique_id,
                    )
                )

        description = "BTagent ATT&CK Coverage"
        if investigation_id:
            description = f"BTagent Coverage for investigation {investigation_id}"

        score_pct = 0.0
        if coverage.total_techniques > 0:
            score_pct = round((coverage.covered_techniques / coverage.total_techniques) * 100, 1)

        return NavigatorLayer(
            name=f"BTagent Coverage ({score_pct}%)",
            description=description,
            techniques=nav_techniques,
            metadata=[
                {"name": "total_techniques", "value": str(coverage.total_techniques)},
                {
                    "name": "covered_techniques",
                    "value": str(coverage.covered_techniques),
                },
                {"name": "coverage_pct", "value": f"{score_pct}%"},
            ],
        )

    # ------------------------------------------------------------------
    # Technique detail
    # ------------------------------------------------------------------

    @staticmethod
    async def get_technique_by_id(
        db: AsyncSession,
        technique_id: str,
    ) -> MitreTechnique | None:
        """Fetch a single technique by ID.

        Parameters
        ----------
        db : AsyncSession
            Request-scoped async DB session.
        technique_id : str
            Technique ID (e.g. T1059.001).

        Returns
        -------
        MitreTechnique | None
        """
        result = await db.execute(
            select(MitreTechniqueRow).where(MitreTechniqueRow.id == technique_id)
        )
        row = result.scalar_one_or_none()
        if not row:
            return None
        return _row_to_technique(row)

    @staticmethod
    async def list_techniques(
        db: AsyncSession,
        *,
        tactic_filter: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[MitreTechnique], int]:
        """List techniques with optional tactic filter and pagination.

        Returns
        -------
        tuple[list[MitreTechnique], int]
            (techniques, total_count)
        """
        base = select(MitreTechniqueRow)
        count_base = select(func.count(MitreTechniqueRow.id))

        if tactic_filter:
            base = base.where(MitreTechniqueRow.tactic == tactic_filter)
            count_base = count_base.where(MitreTechniqueRow.tactic == tactic_filter)

        total_result = await db.execute(count_base)
        total = total_result.scalar() or 0

        stmt = base.order_by(MitreTechniqueRow.id).offset(offset).limit(limit)
        result = await db.execute(stmt)
        rows = result.scalars().all()

        return [_row_to_technique(r) for r in rows], total

    @staticmethod
    async def list_tactics(db: AsyncSession) -> list[MitreTactic]:
        """List all tactics in kill-chain order.

        Returns
        -------
        list[MitreTactic]
        """
        result = await db.execute(select(MitreTacticRow).order_by(MitreTacticRow.ordinal))
        rows = result.scalars().all()
        return [
            MitreTactic(
                id=r.id,
                name=r.name,
                shortname=r.shortname,
                description=r.description or "",
                ordinal=r.ordinal,
            )
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_technique(row: MitreTechniqueRow) -> MitreTechnique:
    """Convert a MitreTechniqueRow to a MitreTechnique Pydantic model."""
    return MitreTechnique(
        id=row.id,
        name=row.name,
        tactic=row.tactic,
        description=row.description or "",
        platforms=row.platforms or [],
        data_sources=row.data_sources or [],
        detection=row.detection or "",
        url=row.url or "",
        is_subtechnique=row.is_subtechnique,
    )
