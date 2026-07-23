"""SQLAlchemy ORM models for MITRE ATT&CK data."""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class MitreTechniqueRow(Base):
    """MITRE ATT&CK technique or sub-technique."""

    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    platforms: Mapped[list] = mapped_column(JSONB, default=list)
    data_sources: Mapped[list] = mapped_column(JSONB, default=list)
    detection: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(500), default="")
    is_subtechnique: Mapped[bool] = mapped_column(default=False)

    __table_args__ = (
        Index("idx_mitre_techniques_tactic", "tactic"),
        Index("idx_mitre_techniques_name", "name"),
    )


class MitreTacticRow(Base):
    """MITRE ATT&CK tactic (kill-chain phase)."""

    __tablename__ = "mitre_tactics"

    id: Mapped[str] = mapped_column(String(10), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    shortname: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (Index("idx_mitre_tactics_ordinal", "ordinal"),)


class MitreGroupRow(Base):
    """MITRE ATT&CK threat group."""

    __tablename__ = "mitre_groups"

    id: Mapped[str] = mapped_column(String(10), primary_key=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    aliases: Mapped[list] = mapped_column(JSONB, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)

    __table_args__ = (Index("idx_mitre_groups_name", "name"),)


class MitreTechniqueTagRow(Base):
    """Tag associating a MITRE technique with an entity (IOC, timeline, etc.)."""

    __tablename__ = "mitre_technique_tags"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    technique_id: Mapped[str] = mapped_column(
        String(20),
        ForeignKey("mitre_techniques.id", ondelete="CASCADE"),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    tagged_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("idx_mitre_tags_technique", "technique_id"),
        Index("idx_mitre_tags_entity", "entity_type", "entity_id"),
        Index("idx_mitre_tags_tagged_by", "tagged_by"),
    )


class TechniqueExerciseRow(Base):
    """When an org last *exercised* an ATT&CK technique via a hunt (#99 Phase C).

    One row per (org, technique), upserted by every plan execution. Powers
    the coverage-map question "which techniques haven't been tested in
    >N days?" — coverage says a detection exists; exercise says the hunt
    machinery actually looked recently. No FK to ``mitre_techniques``:
    hypotheses may cite techniques newer than the seeded corpus, and the
    record of having hunted them must not be droppable by a corpus refresh.
    """

    __tablename__ = "technique_exercises"

    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    last_exercised_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    # Lineage of the most recent exercise.
    last_plan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    last_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # "hit" | "clean" | "errored" — outcome of the most recent exercise.
    last_outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    exercise_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (Index("idx_technique_exercises_org_at", "org_id", "last_exercised_at"),)
