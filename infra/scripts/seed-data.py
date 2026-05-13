#!/usr/bin/env python3
"""Seed database with initial admin user and sample data for development."""

import asyncio
import os
import secrets
import sys

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))

from sqlalchemy import select
from btagent_backend.db.engine import async_session_factory
from btagent_backend.db.models import UserRow, InvestigationRow
from btagent_backend.db.models_mitre import MitreTacticRow, MitreTechniqueRow
from btagent_backend.auth.jwt import hash_password
from btagent_shared.utils.ids import generate_id


# Minimal MITRE ATT&CK fixture so the matrix UI has data to render in
# E2E. The full STIX bundle is ~190+ techniques; the test suite only
# needs (a) a spread of tactics so the matrix grid columns render,
# (b) the well-known probe technique ids the technique-detail tests
# fall back to (T1078 / T1059 / T1566 / T1190 / T1486 / T1003 /
# T1071 / T1027), and (c) one technique whose name contains
# "kerberoast" for the search-narrow test in
# tests/e2e/specs/mitre/matrix.spec.ts:48.
_SEED_MITRE_TACTICS = [
    {"id": "TA0001", "name": "Initial Access",   "shortname": "initial-access",       "ordinal": 1},
    {"id": "TA0002", "name": "Execution",        "shortname": "execution",            "ordinal": 2},
    {"id": "TA0003", "name": "Persistence",      "shortname": "persistence",          "ordinal": 3},
    {"id": "TA0004", "name": "Privilege Escalation", "shortname": "privilege-escalation", "ordinal": 4},
    {"id": "TA0005", "name": "Defense Evasion",  "shortname": "defense-evasion",      "ordinal": 5},
    {"id": "TA0006", "name": "Credential Access","shortname": "credential-access",    "ordinal": 6},
    {"id": "TA0007", "name": "Discovery",        "shortname": "discovery",            "ordinal": 7},
    {"id": "TA0008", "name": "Lateral Movement", "shortname": "lateral-movement",     "ordinal": 8},
    {"id": "TA0009", "name": "Collection",       "shortname": "collection",           "ordinal": 9},
    {"id": "TA0010", "name": "Exfiltration",     "shortname": "exfiltration",         "ordinal": 10},
    {"id": "TA0011", "name": "Command and Control", "shortname": "command-and-control", "ordinal": 11},
    {"id": "TA0040", "name": "Impact",           "shortname": "impact",               "ordinal": 12},
    {"id": "TA0042", "name": "Resource Development", "shortname": "resource-development", "ordinal": 13},
    {"id": "TA0043", "name": "Reconnaissance",   "shortname": "reconnaissance",       "ordinal": 14},
]

_SEED_MITRE_TECHNIQUES = [
    # Probe ids surveyed by tests/e2e/specs/mitre/technique-detail.spec.ts.
    {"id": "T1078", "name": "Valid Accounts",                  "tactic": "initial-access"},
    {"id": "T1059", "name": "Command and Scripting Interpreter","tactic": "execution"},
    {"id": "T1566", "name": "Phishing",                        "tactic": "initial-access"},
    {"id": "T1190", "name": "Exploit Public-Facing Application","tactic": "initial-access"},
    {"id": "T1486", "name": "Data Encrypted for Impact",       "tactic": "impact"},
    {"id": "T1003", "name": "OS Credential Dumping",           "tactic": "credential-access"},
    {"id": "T1071", "name": "Application Layer Protocol",      "tactic": "command-and-control"},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    # Required for the "kerberoast" search-narrow assertion.
    {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactic": "credential-access"},
    {"id": "T1558.003", "name": "Kerberoasting", "tactic": "credential-access", "is_subtechnique": True},
]


async def _seed_mitre_attack(session) -> None:
    """Idempotent: skip if any MITRE tactic already exists."""
    existing = await session.execute(select(MitreTacticRow).limit(1))
    if existing.scalar_one_or_none():
        return
    for tactic in _SEED_MITRE_TACTICS:
        session.add(MitreTacticRow(
            id=tactic["id"],
            name=tactic["name"],
            shortname=tactic["shortname"],
            ordinal=tactic["ordinal"],
            description=f"Seeded MITRE ATT&CK tactic: {tactic['name']}.",
        ))
    for tech in _SEED_MITRE_TECHNIQUES:
        session.add(MitreTechniqueRow(
            id=tech["id"],
            name=tech["name"],
            tactic=tech["tactic"],
            description=f"Seeded MITRE ATT&CK technique: {tech['name']}.",
            platforms=["Windows", "Linux", "macOS"],
            data_sources=[],
            detection="",
            url=f"https://attack.mitre.org/techniques/{tech['id'].replace('.', '/')}/",
            is_subtechnique=tech.get("is_subtechnique", False),
        ))


def _generate_seed_password(username: str = "") -> str:
    """SEC-002 FIX: Generate a random password for seed users instead of using trivial ones.
    In CI/test mode (BTAGENT_ENV=test), use deterministic passwords for UAT."""
    if os.environ.get("BTAGENT_ENV") == "test":
        return username or "test-password"  # Deterministic for CI UAT
    return secrets.token_urlsafe(16)


async def seed():
    async with async_session_factory() as session:
        # MITRE ATT&CK fixture is independent of user seed and idempotent
        # on its own check — seed it before the early-return on admin
        # existence so tests targeting the matrix work even on a DB that
        # already has users but never ran MITRE seeding.
        await _seed_mitre_attack(session)
        await session.commit()

        # Generate passwords for each user (deterministic in test mode, random otherwise)
        admin_pw = _generate_seed_password("admin")
        analyst_pw = _generate_seed_password("analyst1")
        senior_pw = _generate_seed_password("senior1")

        # Check if admin exists
        result = await session.execute(select(UserRow).where(UserRow.username == "admin"))
        existing_admin = result.scalar_one_or_none()
        if existing_admin:
            # In test mode, always reset known users' passwords to the deterministic
            # value so 'admin'/'admin' works even if a stale row exists from a
            # previous non-test seed run.
            if os.environ.get("BTAGENT_ENV") == "test":
                for username, pw in (
                    ("admin", admin_pw),
                    ("analyst1", analyst_pw),
                    ("senior1", senior_pw),
                ):
                    res = await session.execute(
                        select(UserRow).where(UserRow.username == username)
                    )
                    user = res.scalar_one_or_none()
                    if user is not None:
                        user.password_hash = hash_password(pw)
                await session.commit()
                print("Test-mode seed: reset admin/analyst1/senior1 passwords to deterministic values.")
                print(f"  Admin user:    admin / {admin_pw}")
                print(f"  Analyst user:  analyst1 / {analyst_pw}")
                print(f"  Senior user:   senior1 / {senior_pw}")
                return
            print("Admin user already exists, skipping seed.")
            return

        # Create admin user
        admin = UserRow(
            id=generate_id("usr"),
            username="admin",
            email="admin@btagent.local",
            password_hash=hash_password(admin_pw),
            role="admin",
        )
        session.add(admin)

        # Create analyst user
        analyst = UserRow(
            id=generate_id("usr"),
            username="analyst1",
            email="analyst1@btagent.local",
            password_hash=hash_password(analyst_pw),
            role="analyst",
        )
        session.add(analyst)

        # Create senior analyst
        senior = UserRow(
            id=generate_id("usr"),
            username="senior1",
            email="senior1@btagent.local",
            password_hash=hash_password(senior_pw),
            role="senior_analyst",
        )
        session.add(senior)

        # Flush users so FK references work
        await session.flush()

        # Create sample investigation
        inv = InvestigationRow(
            id=generate_id("inv"),
            title="[SEED] Suspicious Login Activity — Admin Account",
            description="Multiple failed login attempts followed by successful auth from unusual IP",
            severity="high",
            tlp_level="amber",
            assigned_to=analyst.id,
            status="pending",
        )
        session.add(inv)

        await session.commit()
        # SEC-P3-002 FIX: Only print credentials in test mode to avoid leaking
        # random production passwords to stdout/CI logs.
        if os.environ.get("BTAGENT_ENV") == "test":
            print("Seed data created (test mode — deterministic credentials):")
            print(f"  Admin user:    admin / {admin_pw}")
            print(f"  Analyst user:  analyst1 / {analyst_pw}")
            print(f"  Senior user:   senior1 / {senior_pw}")
        else:
            print("Seed data created. Credentials are NOT printed in non-test mode.")
            print("  Retrieve or reset passwords via the admin CLI.")
        print(f"  Investigation: {inv.id} — {inv.title}")


if __name__ == "__main__":
    asyncio.run(seed())
