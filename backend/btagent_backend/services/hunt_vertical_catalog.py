"""Findings-vertical catalog — the manual-runnable hunt verticals + their status.

The three findings verticals (email, deception, NDR) each expose a
``POST /hunt/<vertical>/run`` route and a scheduled cron whose enablement +
cadence derive from config (``<vertical>_hunt_schedule_enabled`` /
``<vertical>_hunt_scan_interval_hours``, both mock-first-derived). This module
reflects that config into a read-only catalog so the API (and, later, the UI)
can show at a glance which proactive hunts exist, where to trigger them, and
which are on a cron.

Pure config reflection: no DB, no network. The vertical list is explicit (kept
in lock-step with the run routes and crons) rather than discovered, so adding a
vertical is a deliberate one-line edit the coverage test pins.
"""

from __future__ import annotations

from typing import Any

from btagent_backend.config import get_settings

# Each entry pins one vertical to its run route + the config fields that gate its
# cron. ``windowed`` flags the email vertical as the only time-windowed one (its
# run route accepts a lookback / explicit window; the others are windowless).
_VERTICALS: tuple[dict[str, Any], ...] = (
    {
        "name": "email",
        "domain": "email",
        "source": "email_security",
        "run_route": "/hunt/email/run",
        "windowed": True,
        "schedule_flag": "email_hunt_schedule_enabled",
        "interval_field": "email_hunt_scan_interval_hours",
    },
    {
        "name": "deception",
        "domain": "deception",
        "source": "deception",
        "run_route": "/hunt/deception/run",
        "windowed": False,
        "schedule_flag": "deception_hunt_schedule_enabled",
        "interval_field": "deception_hunt_scan_interval_hours",
    },
    {
        "name": "ndr",
        "domain": "ndr",
        "source": "ndr",
        "run_route": "/hunt/ndr/run",
        "windowed": False,
        "schedule_flag": "ndr_hunt_schedule_enabled",
        "interval_field": "ndr_hunt_scan_interval_hours",
    },
)

# Public tuple of vertical names, in catalog order — the coverage anchor.
VERTICAL_NAMES: tuple[str, ...] = tuple(v["name"] for v in _VERTICALS)


def list_hunt_verticals() -> list[dict[str, Any]]:
    """Return the findings-vertical catalog with each one's live schedule status.

    Reflects the current settings: ``schedule_enabled`` is the derived gate flag
    (mock-first → on in mock mode, off in production until a live connector is
    wired) and ``scan_interval_hours`` the cron cadence.
    """
    settings = get_settings()
    catalog: list[dict[str, Any]] = []
    for v in _VERTICALS:
        catalog.append(
            {
                "name": v["name"],
                "domain": v["domain"],
                "source": v["source"],
                "run_route": v["run_route"],
                "windowed": v["windowed"],
                "schedule_enabled": bool(getattr(settings, v["schedule_flag"])),
                "scan_interval_hours": int(getattr(settings, v["interval_field"])),
            }
        )
    return catalog
