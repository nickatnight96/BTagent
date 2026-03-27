"""Scope enforcement hook — prevents out-of-scope access during investigations.

Checks tool inputs against an allowed scope definition (domains, IPs, CIDR
ranges, hostnames, systems) and blocks tool calls that would target assets
outside the investigation's authorized perimeter.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler

from btagent_agents.events.emitter import RedisEmitter
from btagent_agents.hooks.base import HookProvider
from btagent_shared.types.events import EventType

logger = logging.getLogger("btagent.hooks.scope_enforcement")

# Regex patterns for extracting targets from tool inputs
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_CIDR_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}\b"
)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,})\b"
)


class ScopeViolation(Exception):
    """Raised when a tool call targets an out-of-scope system."""

    def __init__(self, tool_name: str, target: str, reason: str) -> None:
        self.tool_name = tool_name
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation: {tool_name} targeted {target!r} — {reason}")


@dataclass
class InvestigationScope:
    """Defines the authorized perimeter for an investigation.

    All fields are optional. If a field is empty, that dimension is unrestricted.
    When at least one value is set, only those values are allowed.
    """

    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)  # individual IPs
    allowed_cidrs: list[str] = field(default_factory=list)  # CIDR notation
    allowed_hostnames: list[str] = field(default_factory=list)
    allowed_systems: list[str] = field(default_factory=list)  # e.g., "splunk", "crowdstrike"
    blocked_domains: list[str] = field(default_factory=list)
    blocked_ips: list[str] = field(default_factory=list)

    def _ip_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse allowed CIDRs into network objects."""
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in self.allowed_cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid CIDR in scope: %s", cidr)
        return nets

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Check if an IP address is within the allowed scope."""
        # Explicit block list takes priority
        if ip_str in self.blocked_ips:
            return False

        # If no restrictions are defined, allow everything
        if not self.allowed_ips and not self.allowed_cidrs:
            return True

        # Check direct IP match
        if ip_str in self.allowed_ips:
            return True

        # Check CIDR membership
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for net in self._ip_networks():
            if addr in net:
                return True

        return False

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is within the allowed scope."""
        lower = domain.lower().rstrip(".")

        # Explicit block list
        for blocked in self.blocked_domains:
            bl = blocked.lower().rstrip(".")
            if lower == bl or lower.endswith("." + bl):
                return False

        # If no restrictions, allow everything
        if not self.allowed_domains:
            return True

        for allowed in self.allowed_domains:
            al = allowed.lower().rstrip(".")
            if lower == al or lower.endswith("." + al):
                return True

        return False

    def is_hostname_allowed(self, hostname: str) -> bool:
        """Check if a hostname is allowed."""
        if not self.allowed_hostnames:
            return True
        lower = hostname.lower()
        return any(lower == h.lower() for h in self.allowed_hostnames)


def _extract_targets(text: str) -> dict[str, list[str]]:
    """Extract IPs, CIDRs, and domains from a text string."""
    targets: dict[str, list[str]] = {"ips": [], "cidrs": [], "domains": []}

    # CIDRs first (before IPs, since CIDRs contain IPs)
    for match in _CIDR_PATTERN.finditer(text):
        cidr = match.group(0)
        if cidr not in targets["cidrs"]:
            targets["cidrs"].append(cidr)

    # IPs (exclude those already captured as part of CIDRs)
    cidr_ips = {c.split("/")[0] for c in targets["cidrs"]}
    for match in _IP_PATTERN.finditer(text):
        ip = match.group(0)
        if ip not in targets["ips"] and ip not in cidr_ips:
            targets["ips"].append(ip)

    # Domains
    for match in _DOMAIN_PATTERN.finditer(text):
        domain = match.group(0)
        # Exclude things that look like version numbers or IPs already captured
        if domain not in targets["domains"] and not _IP_PATTERN.fullmatch(domain):
            targets["domains"].append(domain)

    return targets


class ScopeEnforcementCallback(AsyncCallbackHandler):
    """LangChain callback that blocks tool calls targeting out-of-scope systems."""

    def __init__(
        self,
        emitter: RedisEmitter,
        scope: InvestigationScope,
        investigation_id: str,
    ) -> None:
        super().__init__()
        self._emitter = emitter
        self._scope = scope
        self._investigation_id = investigation_id

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown_tool")
        targets = _extract_targets(input_str)
        violations: list[str] = []

        # Check IPs
        for ip in targets["ips"]:
            if not self._scope.is_ip_allowed(ip):
                violations.append(f"IP {ip} is out of scope")

        # Check domains
        for domain in targets["domains"]:
            if not self._scope.is_domain_allowed(domain):
                violations.append(f"Domain {domain} is out of scope")

        # Check CIDRs (the entire range must be within scope)
        for cidr in targets["cidrs"]:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                # Check if the network's base address is in scope
                if not self._scope.is_ip_allowed(str(net.network_address)):
                    violations.append(f"CIDR {cidr} is out of scope")
            except ValueError:
                violations.append(f"Invalid CIDR {cidr}")

        if violations:
            violation_detail = "; ".join(violations)
            logger.warning(
                "Scope violation in tool %s: %s",
                tool_name,
                violation_detail,
            )

            await self._emitter.emit(
                EventType.ERROR,
                error=f"Scope violation: {violation_detail}",
                error_type="ScopeViolation",
                source="scope_enforcement",
                tool_name=tool_name,
                violations=violations,
                targets=targets,
            )

            raise ScopeViolation(
                tool_name=tool_name,
                target=violation_detail,
                reason="Tool call targets systems outside the investigation scope",
            )


class ScopeEnforcementHook(HookProvider):
    """Hook that prevents agents from accessing out-of-scope systems.

    Usage::

        scope = InvestigationScope(
            allowed_domains=["acme.com", "internal.acme.com"],
            allowed_cidrs=["10.0.0.0/8", "192.168.1.0/24"],
            blocked_ips=["10.0.0.1"],  # management plane
        )
        hook = ScopeEnforcementHook(emitter, scope, investigation_id)
        registry.register(hook, critical=True)
    """

    def __init__(
        self,
        emitter: RedisEmitter,
        scope: InvestigationScope,
        investigation_id: str,
    ) -> None:
        self._emitter = emitter
        self._scope = scope
        self._investigation_id = investigation_id

    def get_callbacks(self) -> list[BaseCallbackHandler]:
        return [
            ScopeEnforcementCallback(
                emitter=self._emitter,
                scope=self._scope,
                investigation_id=self._investigation_id,
            )
        ]

    @property
    def scope(self) -> InvestigationScope:
        return self._scope
