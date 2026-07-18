"""Recorded Zscaler ZIA (secure web gateway) fixtures for mock mode (#100 Tier-2).

Shapes mirror the Zscaler Internet Access (ZIA) web-transaction log surface the
live connector will call (NSS / cloud-nss feed fields):

- ``ZSCALER_FIXTURE_WEBLOGS`` — web-transaction rows: ``time``, ``user``,
  ``department``, ``url``, ``host``, ``action`` (Allowed/Blocked), ``category``
  (URL category), ``threatName``, ``reqSize``/``respSize``, ``clientIP``.

The fixtures tell one coherent C2-plus-exfil story for ``dkim@example.com``:

* Repeated **Blocked** requests to ``sync-cdn.badhost.example`` — Zscaler
  categorises it ``Malware`` and names the threat — a beacon the proxy stopped.
* A large **Allowed** upload (``respSize`` small, ``reqSize`` large) to
  ``paste.example.io`` — possible data staging that slipped through.
* ``bwallace@example.com`` browses ``docs.example.com`` cleanly — the noise
  floor.

Join discipline: ``user`` is the principal on every row; ``host`` is the
destination for the URL rollup.
"""

from __future__ import annotations

from typing import Any

C2_HOST = "sync-cdn.badhost.example"


def _row(
    *,
    time: str,
    user: str,
    url: str,
    host: str,
    action: str,
    category: str,
    threat_name: str = "",
    req_size: int = 512,
    resp_size: int = 2048,
    client_ip: str = "10.4.2.33",
    department: str = "Finance",
) -> dict[str, Any]:
    return {
        "time": time,
        "user": user,
        "department": department,
        "url": url,
        "host": host,
        "action": action,
        "category": category,
        "threatName": threat_name,
        "reqSize": req_size,
        "respSize": resp_size,
        "clientIP": client_ip,
    }


ZSCALER_FIXTURE_WEBLOGS: list[dict[str, Any]] = [
    # --- blocked C2 beacon burst against dkim ---
    _row(
        time="2026-07-14T10:00:05Z",
        user="dkim@example.com",
        url="https://sync-cdn.badhost.example/beacon",
        host=C2_HOST,
        action="Blocked",
        category="Malware",
        threat_name="Trojan.GenericBeacon",
    ),
    _row(
        time="2026-07-14T10:05:05Z",
        user="dkim@example.com",
        url="https://sync-cdn.badhost.example/beacon",
        host=C2_HOST,
        action="Blocked",
        category="Malware",
        threat_name="Trojan.GenericBeacon",
    ),
    _row(
        time="2026-07-14T10:10:05Z",
        user="dkim@example.com",
        url="https://sync-cdn.badhost.example/beacon",
        host=C2_HOST,
        action="Blocked",
        category="Malware",
        threat_name="Trojan.GenericBeacon",
    ),
    # --- large allowed upload to a paste site (possible exfil staging) ---
    _row(
        time="2026-07-14T11:30:00Z",
        user="dkim@example.com",
        url="https://paste.example.io/upload",
        host="paste.example.io",
        action="Allowed",
        category="Web Hosting",
        req_size=5_242_880,  # 5 MB out
        resp_size=256,
    ),
    # --- clean comparison browsing ---
    _row(
        time="2026-07-14T13:15:00Z",
        user="bwallace@example.com",
        url="https://docs.example.com/handbook",
        host="docs.example.com",
        action="Allowed",
        category="Professional Services",
        client_ip="10.6.0.18",
        department="Engineering",
    ),
]
