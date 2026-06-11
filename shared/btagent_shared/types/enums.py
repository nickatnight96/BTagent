"""Shared enumerations used across BTagent."""

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InvestigationStatus(StrEnum):
    PENDING = "pending"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    PAUSED = "paused"
    PAUSED_HITL = "paused_hitl"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    CVE = "cve"
    USER_AGENT = "user_agent"
    MUTEX = "mutex"
    PROCESS_NAME = "process_name"
    # ``other`` is the frontend-side catch-all; mirrored here so the
    # backend Pydantic schemas (now typed against this enum) accept what
    # the import modal already emits.
    OTHER = "other"


class ContainmentStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


class UserRole(StrEnum):
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    INCIDENT_COMMANDER = "incident_commander"
    ADMIN = "admin"


class AuditCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    CONFIG_CHANGE = "config_change"
    AGENT_ACTION = "agent_action"
    DATA_ACCESS = "data_access"
    # Workflow CRUD lifecycle transitions (publish / deprecate /
    # auto_deprecate / delete) — Phase 2 v2 workflow store.
    WORKFLOW = "workflow"
    # Hunt triage lifecycle actions (suppress / promote) — Phase 6 (#119).
    # Suppressing shapes what the SOC stops looking at and promoting spawns
    # an investigation, so both must land on the hash-chain ledger.
    HUNT = "hunt"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
