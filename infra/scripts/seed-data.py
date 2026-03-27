#!/usr/bin/env python3
"""Seed database with initial admin user and sample data for development."""

import asyncio
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))

from sqlalchemy import select
from btagent_backend.db.engine import async_session_factory
from btagent_backend.db.models import UserRow, InvestigationRow
from btagent_backend.auth.jwt import hash_password
from btagent_shared.utils.ids import generate_id


async def seed():
    async with async_session_factory() as session:
        # Check if admin exists
        result = await session.execute(select(UserRow).where(UserRow.username == "admin"))
        if result.scalar_one_or_none():
            print("Admin user already exists, skipping seed.")
            return

        # Create admin user
        admin = UserRow(
            id=generate_id("usr"),
            username="admin",
            email="admin@btagent.local",
            password_hash=hash_password("admin"),
            role="admin",
        )
        session.add(admin)

        # Create analyst user
        analyst = UserRow(
            id=generate_id("usr"),
            username="analyst1",
            email="analyst1@btagent.local",
            password_hash=hash_password("analyst1"),
            role="analyst",
        )
        session.add(analyst)

        # Create senior analyst
        senior = UserRow(
            id=generate_id("usr"),
            username="senior1",
            email="senior1@btagent.local",
            password_hash=hash_password("senior1"),
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
        print("Seed data created:")
        print(f"  Admin user:    admin / admin")
        print(f"  Analyst user:  analyst1 / analyst1")
        print(f"  Senior user:   senior1 / senior1")
        print(f"  Investigation: {inv.id} — {inv.title}")


if __name__ == "__main__":
    asyncio.run(seed())
