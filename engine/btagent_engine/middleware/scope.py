"""Scope-enforcement middleware -- blocks out-of-investigation targets.

Engine-side port of ``agents/btagent_agents/hooks/scope_enforcement_hook.py``.
The :class:`InvestigationScope` model and the IP/CIDR/domain extraction
regexes mirror the legacy hook one-for-one. Behaviour change: the
middleware applies to *every* node, not just LangChain tool starts, since
an integration node's input is the natural place for an "in scope" check.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel as _BaseModel
from pydantic import ConfigDict, Field

from btagent_engine.middleware.base import Middleware

if TYPE_CHECKING:
    from pydantic import BaseModel

    from btagent_engine.node import Node, NodeContext


logger = logging.getLogger("btagent.engine.middleware.scope")


# IPv4-only patterns -- IPv6 is not in scope for v1 of the regex; an IPv6
# address inside an input still gets through, but the InvestigationScope
# model handles IPv6 CIDR membership correctly via ``ipaddress``.
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_CIDR_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}\b"
)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b"
)


class ScopeViolation(Exception):
    """Raised when a node's input targets an out-of-scope asset."""

    def __init__(self, node_id: str, target: str, reason: str) -> None:
        self.node_id = node_id
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation: {node_id} targeted {target!r} -- {reason}")


class InvestigationScope(_BaseModel):
    """Authorised perimeter for an investigation.

    Empty list on a dimension == that dimension is unrestricted. A non-empty
    allow-list means *only* the listed values pass. Block-lists override
    allow-lists.
    """

    model_config = ConfigDict(extra="forbid")

    allowed_domains: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_hostnames: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    blocked_ips: list[str] = Field(default_factory=list)

    def _ip_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in self.allowed_cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid CIDR in scope: %s", cidr)
        return nets

    def is_ip_allowed(self, ip_str: str) -> bool:
        if ip_str in self.blocked_ips:
            return False
        if not self.allowed_ips and not self.allowed_cidrs:
            return True
        if ip_str in self.allowed_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for net in self._ip_networks():
            if addr in net:
                return True
        return False

    def is_domain_allowed(self, domain: str) -> bool:
        lower = domain.lower().rstrip(".")
        for blocked in self.blocked_domains:
            bl = blocked.lower().rstrip(".")
            if lower == bl or lower.endswith("." + bl):
                return False
        if not self.allowed_domains:
            return True
        for allowed in self.allowed_domains:
            al = allowed.lower().rstrip(".")
            if lower == al or lower.endswith("." + al):
                return True
        return False


def _extract_targets(text: str) -> dict[str, list[str]]:
    """Pull IPs, CIDRs, and domains out of free-form text."""
    targets: dict[str, list[str]] = {"ips": [], "cidrs": [], "domains": []}

    for match in _CIDR_PATTERN.finditer(text):
        cidr = match.group(0)
        if cidr not in targets["cidrs"]:
            targets["cidrs"].append(cidr)

    cidr_ips = {c.split("/")[0] for c in targets["cidrs"]}
    for match in _IP_PATTERN.finditer(text):
        ip = match.group(0)
        if ip not in targets["ips"] and ip not in cidr_ips:
            targets["ips"].append(ip)

    for match in _DOMAIN_PATTERN.finditer(text):
        domain = match.group(0)
        if domain not in targets["domains"] and not _IP_PATTERN.fullmatch(domain):
            targets["domains"].append(domain)

    return targets


def _flatten_strings(value: Any) -> str:
    """Concatenate every string value reachable from *value* into one blob.

    Walks dicts and lists/tuples. Non-string scalars are stringified so
    integer-encoded IPs (rare but possible in some IOC formats) are still
    visible to the regex. Depth-limited to keep runaway nesting cheap.
    """
    parts: list[str] = []

    def _walk(node: Any, depth: int) -> None:
        if depth > 12:
            return
        if isinstance(node, str):
            parts.append(node)
            return
        if isinstance(node, dict):
            for v in node.values():
                _walk(v, depth + 1)
            return
        if isinstance(node, list | tuple | set | frozenset):
            for item in node:
                _walk(item, depth + 1)
            return
        if node is None or isinstance(node, bool):
            return
        # Everything else: cheap str() so an int IP fragment isn't lost.
        parts.append(str(node))

    _walk(value, depth=0)
    return "\n".join(parts)


class ScopeEnforcementMiddleware(Middleware):
    """Reject node runs whose input targets out-of-scope assets."""

    name = "scope_enforcement"

    def __init__(self, scope: InvestigationScope) -> None:
        self._scope = scope

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        text = _flatten_strings(input.model_dump(mode="json"))
        targets = _extract_targets(text)

        violations: list[str] = []

        for ip in targets["ips"]:
            if not self._scope.is_ip_allowed(ip):
                violations.append(f"IP {ip} is out of scope")

        for domain in targets["domains"]:
            if not self._scope.is_domain_allowed(domain):
                violations.append(f"Domain {domain} is out of scope")

        for cidr in targets["cidrs"]:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if not self._scope.is_ip_allowed(str(net.network_address)):
                    violations.append(f"CIDR {cidr} is out of scope")
            except ValueError:
                violations.append(f"Invalid CIDR {cidr}")

        if violations:
            detail = "; ".join(violations)
            logger.warning("Scope violation in node %s: %s", node.meta.id, detail)
            raise ScopeViolation(
                node_id=node.meta.id,
                target=detail,
                reason="Node input targets assets outside the investigation scope",
            )


__all__ = [
    "InvestigationScope",
    "ScopeEnforcementMiddleware",
    "ScopeViolation",
]
