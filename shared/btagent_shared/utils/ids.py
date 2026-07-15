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
    "pbe": "pbe",  # Playbook execution
    "cp": "cp",  # Checkpoint (HITL)
    "rpt": "rpt",  # Report
    "ntf": "ntf",  # Notification
    "org": "org",  # Organization (tenant scope)
    "hfnd": "hfnd",  # Hunt finding
    "hclu": "hclu",  # Hunt finding cluster
    "supp": "supp",  # Suppression rule
    "bent": "bent",  # Behavioral entity (#114)
    "bprof": "bprof",  # Behavioral profile (#114)
    "bout": "bout",  # Behavioral outlier (#114)
    "hrun": "hrun",  # Hunt pack run (engine transient run id, #112)
    "hpkrun": "hpkrun",  # Persisted hunt pack-run history row (#112 integration)
    "ws": "ws",  # Weak signal (cross-investigation pattern hunter, #120)
    "phpr": "phpr",  # Pattern-hunt proposal (#120)
    "hplan": "hplan",  # Compiled hunt plan for an accepted proposal (#120 Phase C)
    "plrun": "plrun",  # Persisted hunt-plan run history row (#120 follow-up)
}


def generate_id(prefix: str = "id") -> str:
    """Generate a prefixed ULID.

    Args:
        prefix: Entity type prefix (e.g., 'inv', 'ioc', 'evt').

    Returns:
        String like 'inv_01HX7Z...' — sortable, unique, human-readable prefix.
    """
    return f"{prefix}_{ULID()}"
