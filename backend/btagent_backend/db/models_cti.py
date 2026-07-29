"""SQLAlchemy ORM models for the CTI → Detection pipeline (#113) and the
TAXII 2.1 feed store (#105 / UC-2.1).

Three tables, org-scoped + indexed:

* ``detection_proposals`` — a persisted Sigma rule proposal derived from a
  STIX indicator, carrying the analyst review lifecycle. Uniqueness is
  ``(org_id, source_stix_id)``: re-processing the same bundle *upserts* the
  proposal content instead of spamming duplicates, and a proposal an analyst
  has already decided (accepted / rejected) keeps its decision — only
  still-``proposed`` rows are refreshed (see
  :func:`btagent_backend.services.cti_detection_service.persist_proposals`).
* ``stix_bundles`` — the raw STIX 2.1 bundle behind a propose call, kept so a
  later request can re-run the pipeline by ``stix_bundle_id`` instead of
  re-uploading the bundle. Uniqueness is ``(org_id, bundle_id)``: re-importing
  the same bundle upserts its stored copy.
* ``taxii_feeds`` — one org-scoped TAXII 2.1 collection subscription: where to
  poll, how often, the ``${secret:...}`` *reference* that resolves its
  credential (never the credential itself), and the incremental poll cursor.
  Uniqueness is ``(org_id, name)``.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class DetectionProposalRow(Base):
    """One Sigma rule proposal from the STIX → Sigma pipeline, with review state."""

    __tablename__ = "detection_proposals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Deterministic pipeline id (derived from source_stix_id) — kept alongside
    # the row PK so responses can correlate back to a propose call's output.
    proposal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_stix_id: Mapped[str] = mapped_column(String(256), nullable=False)
    # Bundle provenance — the STIX bundle id the proposal came from (nullable;
    # ad-hoc bundles may carry no id).
    bundle_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    sigma_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    # Analyst-edited "final" rule body (#113 Phase C draft-edit path). None
    # until a proposal is selected + edited via the Engineer UI; when set the
    # row's ``state`` is ``modified`` and the composer ships this body (cited as
    # *edited from draft*) instead of ``sigma_yaml``.
    final_sigma_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSONB list[str] of ATT&CK technique ids.
    technique_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    rationale: Mapped[str] = mapped_column(Text, default="")
    # ``ProposalState`` value (proposed / accepted / rejected / modified).
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    # Historical-telemetry validation outcome (#113 slice 2): serialised
    # RuleValidationResult (per-backend hit counts / errors + verdict).
    # None until POST /cti/proposals/{id}/validate runs.
    validation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Detection-repo PR back-link (#113 slice 3): set by the composer; a
    # non-null value means the rule already shipped and blocks re-composition.
    pr_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Detection-repo PR lifecycle (#113 Phase C closed loop): ``PROutcome``
    # value (proposed / pr_opened / merged / rejected). Advances to ``pr_opened``
    # when the composer ships the rule; a recorded merge outcome flips it to
    # ``merged`` and drives the auto-install + validation closed loop.
    pr_outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    # Review provenance — set when an analyst decides.
    review_rationale: Mapped[str] = mapped_column(Text, default="")
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_detection_proposals_org_id", "org_id"),
        # Upsert key: one proposal per (org, source indicator).
        Index("idx_detection_proposals_source", "org_id", "source_stix_id", unique=True),
        Index("idx_detection_proposals_state", "org_id", "state"),
    )


class StixBundleRow(Base):
    """A raw STIX 2.1 bundle persisted for later bundle-by-id re-processing."""

    __tablename__ = "stix_bundles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The bundle's own STIX id (``bundle--...``) — the key a ``stix_bundle_id``
    # propose request resolves against. Unique per org so re-imports upsert.
    bundle_id: Mapped[str] = mapped_column(String(256), nullable=False)
    # The verbatim bundle dict (``{"type": "bundle", "objects": [...]}``).
    bundle: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # TLP the bundle was imported under (provenance; the pipeline re-gates on
    # the bundle's own object markings + the caller's active TLP at resolve time).
    tlp: Mapped[str] = mapped_column(String(16), nullable=False, default="green")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        # Upsert key: one stored bundle per (org, bundle id).
        Index("idx_stix_bundles_org_bundle", "org_id", "bundle_id", unique=True),
    )


class TaxiiFeedRow(Base):
    """One org-scoped TAXII 2.1 collection subscription (#105 / UC-2.1).

    Config only — **never** credential material. ``auth_secret_ref`` holds a
    single ``${secret:vault:...}`` / ``${secret:aws:...}`` / ``${env:VAR}``
    reference, validated on write by
    :func:`btagent_backend.services.taxii_feed_service.create_feed`; the raw
    token lives in Vault / AWS SM / env and is resolved lazily, at poll time,
    by the poll service.
    """

    __tablename__ = "taxii_feeds"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Operator-facing label; unique per org so a feed can be referred to by name.
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # TAXII 2.1 api-root URL (e.g. https://taxii.example.test/api1). Validated
    # http(s) with no embedded credentials.
    server_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    collection_id: Mapped[str] = mapped_column(String(200), nullable=False)
    # "none" | "bearer" | "basic".
    auth_style: Mapped[str] = mapped_column(String(16), nullable=False, default="none")
    # A ``${secret:...}`` reference — NEVER inline material. Empty for
    # ``auth_style="none"``.
    auth_secret_ref: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    poll_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Incremental cursor: the TAXII ``X-TAXII-Date-Added-Last`` of the newest
    # page ingested. Passed back as ``added_after`` on the next poll.
    last_cursor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Best-effort sweep telemetry: "" (never polled) | "ok" | "error".
    last_status: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    # Scrubbed failure reason from the most recent poll (never carries secrets).
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    objects_ingested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Destination case for polled indicators. Nullable: the poll job
    # lazily provisions a per-feed intake investigation on first ingest and
    # stores its id here.
    intake_investigation_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        # One feed per (org, name); the org prefix keeps every lookup tenant-scoped.
        Index("idx_taxii_feeds_org_name", "org_id", "name", unique=True),
        # The sweep's "enabled feeds, org by org" scan.
        Index("idx_taxii_feeds_org_enabled", "org_id", "enabled"),
    )
