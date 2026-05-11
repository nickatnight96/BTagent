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


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
