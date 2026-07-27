"""Never-block safelist policy (collateral-outage guard) — EPIC-3 (#106).

A :class:`SafelistPolicy` is the single source of truth for "targets that must
never be blocked". It is consulted in two places that must agree:

* **Planning** (``btagent_engine.reasoning.bulk_mitigation``) — a safelisted IOC
  is proposed as ``skip_allowlisted`` rather than ``block``.
* **Execution** (``btagent_backend...containment_execute_service``) — a
  safelisted target is *refused* before any dispatch, with an audited denial.

Historically the never-block set was a pair of hard-coded module frozensets
inside the bulk-mitigation node. #106 replaces that with a composable policy: a
**universal baseline** (:data:`BASELINE_SAFELIST` — well-known public resolvers
and critical-infrastructure domain suffixes, plus the always-on structural
guard for RFC1918 / loopback / reserved / link-local / multicast IPs) that an
**org-scoped** ``response_safelist`` table extends. Operators add org entries
through the API with no code change; the baseline keeps a fresh org safe by
default.

The policy carries no I/O and no heavy deps so both the engine and the backend
can import it without crossing package boundaries.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace

# --------------------------------------------------------------------------- #
# Universal baseline (was the hard-coded allowlist in bulk_mitigation.py)
# --------------------------------------------------------------------------- #

# Well-known public resolvers — blocking these breaks name resolution org-wide.
_BASELINE_IPS: frozenset[str] = frozenset(
    {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}
)
# Critical-infrastructure domains — blocking these is almost always a misfire.
_BASELINE_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "microsoft.com",
    "windowsupdate.com",
    "office.com",
    "office365.com",
    "google.com",
    "googleapis.com",
    "apple.com",
    "amazonaws.com",
    "cloudflare.com",
    "akamai.net",
    "icloud.com",
)


def is_structurally_reserved_ip(value: str) -> bool:
    """True for non-public IPs (RFC1918 / loopback / reserved / link-local / multicast).

    These are *always* refused for blocking regardless of org policy — pushing a
    perimeter deny for one's own internal ranges is a self-inflicted outage.
    Malformed input returns ``False`` (validation is a separate concern).
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast


def domain_from_url(value: str) -> str:
    """Extract the host from a URL (scheme/path/query/fragment stripped)."""
    s = re.sub(r"^https?://", "", value.strip(), flags=re.I)
    return s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]


@dataclass(frozen=True)
class SafelistPolicy:
    """A never-block set: exact IPs plus domain suffixes.

    Structural-reserved IPs are always safelisted (see
    :func:`is_structurally_reserved_ip`) in addition to ``ips``. Domain matching
    is suffix-based: an entry ``example.com`` safelists ``example.com`` and any
    ``*.example.com`` subdomain. Values are normalized (trim + lowercase) on
    construction so lookups are case-insensitive.
    """

    ips: frozenset[str] = field(default_factory=frozenset)
    domain_suffixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "ips", frozenset(v.strip() for v in self.ips if v and v.strip()))
        object.__setattr__(
            self,
            "domain_suffixes",
            tuple(s.strip().lower().rstrip(".") for s in self.domain_suffixes if s and s.strip()),
        )

    def ip_safelisted(self, value: str) -> bool:
        v = value.strip()
        return is_structurally_reserved_ip(v) or v in self.ips

    def domain_safelisted(self, value: str) -> bool:
        host = value.strip().lower().rstrip(".")
        if not host:
            return False
        return any(host == s or host.endswith("." + s) for s in self.domain_suffixes)

    def url_safelisted(self, value: str) -> bool:
        return self.domain_safelisted(domain_from_url(value))

    def merge(
        self,
        *,
        extra_ips: object = (),
        extra_domain_suffixes: object = (),
    ) -> SafelistPolicy:
        """Return a new policy layering org-scoped entries on top of this one."""
        ips = set(self.ips)
        ips.update(v.strip() for v in (extra_ips or ()) if v and str(v).strip())
        suffixes = list(self.domain_suffixes)
        suffixes.extend(
            str(s).strip().lower().rstrip(".")
            for s in (extra_domain_suffixes or ())
            if s and str(s).strip()
        )
        return replace(self, ips=frozenset(ips), domain_suffixes=tuple(suffixes))


# The universal baseline every org inherits. Org ``response_safelist`` rows are
# merged on top of this at planning + execution time.
BASELINE_SAFELIST = SafelistPolicy(
    ips=_BASELINE_IPS,
    domain_suffixes=_BASELINE_DOMAIN_SUFFIXES,
)


__all__ = [
    "BASELINE_SAFELIST",
    "SafelistPolicy",
    "domain_from_url",
    "is_structurally_reserved_ip",
]
