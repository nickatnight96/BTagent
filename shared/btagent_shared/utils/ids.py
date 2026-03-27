"""Prefixed ULID generation for BTagent entities."""

from ulid import ULID

# Prefix mapping for entity types
PREFIXES = {
    "inv": "inv",  # Investigation
    "ioc": "ioc",  # Indicator of Compromise
    "evt": "evt",  # Event
    "usr": "usr",  # User
    "aud": "aud",  # Audit log entry
    "evi": "evi",  # Evidence
    "tl": "tl",  # Timeline entry
    "ca": "ca",  # Containment action
    "ct": "ct",  # Cost tracking
    "pb": "pb",  # Playbook
    "cp": "cp",  # Checkpoint (HITL)
    "rpt": "rpt",  # Report
    "ntf": "ntf",  # Notification
}


def generate_id(prefix: str = "id") -> str:
    """Generate a prefixed ULID.

    Args:
        prefix: Entity type prefix (e.g., 'inv', 'ioc', 'evt').

    Returns:
        String like 'inv_01HX7Z...' — sortable, unique, human-readable prefix.
    """
    return f"{prefix}_{ULID()}"
