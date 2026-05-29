"""BulkMitigationNode — bulk IOC block & mitigation assistant (EPIC-3 UC-3.3).

Given a batch of IOCs an analyst wants to block, produce a per-tool
:class:`MitigationPlan`: for each IOC, decide whether to block, validate it,
screen it against a never-block allowlist, route it to the connector + policy
object that would enforce the block, and render a policy-change preview plus a
rollback.

Safety-by-design:

* **Allowlist is checked first** — RFC1918 / loopback / reserved IPs,
  well-known public resolvers, critical-infrastructure domains, plus any
  caller-supplied exact values are *never* blocked (self-outage guard).
* **Validation per IOC type** — malformed values are skipped, not blocked.
* **Deterministic decisions.** Block/skip routing comes from vetted rules,
  never the LLM — the model can't invent a block. The LLM (when registered)
  only refines the plan *summary*.
* **Nothing executes.** Block actions are ``destructive`` +
  ``requires_approval`` with a ``rollback``. Proposal only.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Callable
from typing import ClassVar, NamedTuple

from btagent_shared.types.enums import IOCType
from btagent_shared.types.mitigation import (
    MitigationAction,
    MitigationDecision,
    MitigationPlan,
)
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_LLM", "true").strip().lower() != "false"


# --------------------------------------------------------------------------- #
# Never-block allowlist (self-inflicted-outage guard)
# --------------------------------------------------------------------------- #

# Well-known public resolvers — blocking these breaks name resolution org-wide.
_ALLOWLIST_IPS: frozenset[str] = frozenset(
    {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}
)
# Critical infrastructure domains — blocking these is almost always a misfire.
_ALLOWLIST_DOMAIN_SUFFIXES: tuple[str, ...] = (
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


def _ip_is_allowlisted(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    # Never block non-public IPs or the known resolvers.
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast:
        return True
    return value in _ALLOWLIST_IPS


def _domain_is_allowlisted(value: str) -> bool:
    host = value.lower().strip().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in _ALLOWLIST_DOMAIN_SUFFIXES)


# --------------------------------------------------------------------------- #
# Per-IOC-type validation
# --------------------------------------------------------------------------- #

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _valid_domain(v: str) -> bool:
    return bool(_DOMAIN_RE.match(v.strip().rstrip(".")))


def _valid_url(v: str) -> bool:
    s = v.strip()
    return s.startswith(("http://", "https://")) and len(s) > 10


def _domain_from_url(v: str) -> str:
    s = re.sub(r"^https?://", "", v.strip(), flags=re.I)
    return s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]


# --------------------------------------------------------------------------- #
# Per-IOC-type block routing (connector + policy object)
# --------------------------------------------------------------------------- #


class _Route(NamedTuple):
    tool: str
    policy_object: str
    validator: Callable[[str], bool]


_ROUTES: dict[IOCType, _Route] = {
    IOCType.IP: _Route("panorama", "perimeter-blocklist", _valid_ip),
    IOCType.DOMAIN: _Route("umbrella", "dns-denylist", _valid_domain),
    IOCType.URL: _Route("zscaler", "url-blocklist", _valid_url),
    IOCType.HASH_MD5: _Route("crowdstrike", "ioc-blocklist", lambda v: bool(_MD5_RE.match(v))),
    IOCType.HASH_SHA1: _Route("crowdstrike", "ioc-blocklist", lambda v: bool(_SHA1_RE.match(v))),
    IOCType.HASH_SHA256: _Route(
        "crowdstrike", "ioc-blocklist", lambda v: bool(_SHA256_RE.match(v))
    ),
    IOCType.EMAIL: _Route("email_gateway", "sender-blocklist", lambda v: "@" in v and "." in v),
}

# IOC kinds with no automated block path (informational / requires manual action).
_UNSUPPORTED: frozenset[IOCType] = frozenset(
    {
        IOCType.FILE_PATH,
        IOCType.REGISTRY_KEY,
        IOCType.CVE,
        IOCType.USER_AGENT,
        IOCType.MUTEX,
        IOCType.PROCESS_NAME,
        IOCType.OTHER,
    }
)


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class IOCRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IOCType
    value: str


class BulkMitigationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iocs: list[IOCRef] = Field(default_factory=list)
    extra_allowlist: list[str] = Field(
        default_factory=list, description="Caller-supplied exact values to never block."
    )


class BulkMitigationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan: MitigationPlan
    mock_mode: bool = Field(..., description="False only when the LLM refined the summary.")


# --------------------------------------------------------------------------- #
# Deterministic plan builder
# --------------------------------------------------------------------------- #


def _allowlisted(ioc: IOCRef, extra: frozenset[str]) -> bool:
    if ioc.value.strip() in extra:
        return True
    if ioc.type == IOCType.IP:
        return _ip_is_allowlisted(ioc.value.strip())
    if ioc.type == IOCType.DOMAIN:
        return _domain_is_allowlisted(ioc.value)
    if ioc.type == IOCType.URL:
        return _domain_is_allowlisted(_domain_from_url(ioc.value))
    return False


def _build_plan(iocs: list[IOCRef], extra_allowlist: list[str]) -> MitigationPlan:
    extra = frozenset(v.strip() for v in extra_allowlist if v.strip())
    actions: list[MitigationAction] = []
    seen: set[tuple[IOCType, str]] = set()
    block_count = 0
    skip_count = 0
    tools: list[str] = []
    seq = 0

    for ioc in iocs:
        seq += 1
        value = ioc.value.strip()
        key = (ioc.type, value.lower())

        if not value:
            skip_count += 1
            actions.append(_skip(seq, ioc, MitigationDecision.SKIP_INVALID, "Empty IOC value."))
            continue
        if key in seen:
            skip_count += 1
            actions.append(
                _skip(seq, ioc, MitigationDecision.SKIP_DUPLICATE, "Already in this batch.")
            )
            continue
        seen.add(key)

        if _allowlisted(ioc, extra):
            skip_count += 1
            actions.append(
                _skip(
                    seq,
                    ioc,
                    MitigationDecision.SKIP_ALLOWLISTED,
                    "Matches the never-block allowlist (would risk a self-inflicted outage).",
                )
            )
            continue

        if ioc.type in _UNSUPPORTED:
            skip_count += 1
            actions.append(
                _skip(
                    seq,
                    ioc,
                    MitigationDecision.SKIP_UNSUPPORTED,
                    f"No automated block path for {ioc.type.value}; handle manually.",
                )
            )
            continue

        route = _ROUTES.get(ioc.type)
        if route is None or not route.validator(value):
            skip_count += 1
            actions.append(
                _skip(
                    seq,
                    ioc,
                    MitigationDecision.SKIP_INVALID,
                    f"Malformed {ioc.type.value} value.",
                )
            )
            continue

        # Well-formed, not allowlisted, supported -> propose a block.
        block_count += 1
        if route.tool not in tools:
            tools.append(route.tool)
        preview = f"+ {route.tool}:{route.policy_object} ADD {ioc.type.value}={value} (action=deny)"
        actions.append(
            MitigationAction(
                id=f"mit_{seq:03d}",
                ioc_type=ioc.type,
                ioc_value=value,
                decision=MitigationDecision.BLOCK,
                tool=route.tool,
                policy_object=route.policy_object,
                policy_preview=preview,
                description=f"Block {ioc.type.value} {value} on {route.tool} ({route.policy_object})",
                destructive=True,
                requires_approval=True,
                rollback=f"Remove {value} from {route.tool}:{route.policy_object}",
            )
        )

    summary = (
        f"{block_count} block action(s) across {len(tools)} tool(s); "
        f"{skip_count} IOC(s) skipped "
        f"({_skip_breakdown(actions)}). All blocks require approval before execution."
    )
    return MitigationPlan(
        summary=summary,
        actions=actions,
        block_count=block_count,
        skip_count=skip_count,
        tools=tools,
    )


def _skip(seq: int, ioc: IOCRef, decision: MitigationDecision, reason: str) -> MitigationAction:
    return MitigationAction(
        id=f"mit_{seq:03d}",
        ioc_type=ioc.type,
        ioc_value=ioc.value.strip(),
        decision=decision,
        description=f"Skip {ioc.type.value} {ioc.value.strip() or '(empty)'}",
        reason=reason,
    )


def _skip_breakdown(actions: list[MitigationAction]) -> str:
    counts: dict[str, int] = {}
    for a in actions:
        if a.decision != MitigationDecision.BLOCK:
            counts[a.decision.value] = counts.get(a.decision.value, 0) + 1
    if not counts:
        return "none"
    return ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #


@NodeRegistry.register
class BulkMitigationNode(Node[BulkMitigationInput, BulkMitigationOutput]):
    """Plan a bulk IOC block across connectors (proposal only)."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.bulk_mitigation",
        name="Bulk IOC Block & Mitigation Assistant",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Plan a bulk IOC block: per-IOC allowlist screening + validation, "
            "per-tool connector/policy routing, a policy-change preview and "
            "rollback for each block. Block/skip decisions are deterministic "
            "(never LLM-invented); every block is flagged for approval. "
            "Executes nothing."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = BulkMitigationInput
    output_schema: ClassVar[type[BaseModel]] = BulkMitigationOutput

    async def run(self, input: BulkMitigationInput, ctx: NodeContext) -> BulkMitigationOutput:
        # Decisions are ALWAYS deterministic (safety). The LLM, when registered
        # + mock off, only refines the human-readable plan summary.
        plan = _build_plan(input.iocs, input.extra_allowlist)

        from btagent_engine.llm import get_llm_client

        client = get_llm_client()
        if not _mock_mode_enabled() and client is not None:
            try:
                summary = await self._llm_summary(plan, client, ctx)
                if summary:
                    plan = plan.model_copy(update={"summary": summary})
                    return BulkMitigationOutput(plan=plan, mock_mode=False)
            except Exception:  # noqa: BLE001 - LLM failure must degrade, not crash
                import logging

                logging.getLogger("btagent.reasoning.bulk_mitigation").warning(
                    "LLM summary refinement failed; using deterministic summary",
                    exc_info=True,
                )
        return BulkMitigationOutput(plan=plan, mock_mode=True)

    async def _llm_summary(self, plan: MitigationPlan, client, ctx) -> str | None:
        """LLM refines ONLY the plan summary (not the per-IOC decisions)."""
        from btagent_shared.types.config import TLP, ModelTier

        from btagent_engine.reasoning._llm_json import call_llm_json, wrap_external_data

        system = (
            "You are an incident-response lead reviewing a bulk IOC-block plan. "
            "Write a crisp 1-2 sentence summary an approver can read at a glance. "
            'Respond ONLY with a JSON object: {"summary": str}. Do NOT change any '
            "block/skip decision; the action list is fixed and authoritative."
        )
        try:
            tlp = TLP(ctx.tlp_level)
        except ValueError:
            tlp = TLP.RED  # fail closed
        lines = "; ".join(
            f"{a.decision.value}:{a.ioc_type.value}={a.ioc_value or 'n/a'}" for a in plan.actions
        )
        user = wrap_external_data(
            f"block_count: {plan.block_count}\nskip_count: {plan.skip_count}\n"
            f"tools: {plan.tools}\nactions: {lines}"
        )
        raw = await call_llm_json(
            client, system=system, user=user, tlp=tlp, tier=ModelTier.STANDARD, array=False
        )
        if not isinstance(raw, dict):
            return None
        summary = str(raw.get("summary") or "").strip()
        return summary or None


__all__ = [
    "BulkMitigationInput",
    "BulkMitigationNode",
    "BulkMitigationOutput",
    "IOCRef",
]
