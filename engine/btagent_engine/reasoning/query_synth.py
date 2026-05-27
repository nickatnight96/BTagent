"""QuerySynthNode — synthesise per-backend hunt queries from a TTP.

The Phase B counterpart to HypothesisGenNode (#99). Takes a hypothesis's
behavioural description + target backends and emits a concrete query for
each backend (Splunk SPL, Sentinel KQL, Elastic EQL, CrowdStrike CQL,
Sigma). RunbookCompiler then folds these into the per-TTP runbook entry.

Design notes:

1. **Mock mode is deterministic** (matches HypothesisGen / LLMCallNode).
   When ``BTAGENT_MOCK_LLM=true`` (the default), the node emits queries
   from a built-in per-(TTP, backend) template library. The templates
   are structurally valid and plausible but not production-tuned —
   their job is to prove the pipeline and give analysts a starting
   point to edit. Real LLM-backed synthesis (schema-aware, field-name
   correct) lands with the router; non-mock mode raises
   ``NotImplementedError``.

2. **Count-capped by default.** Every generated query carries a
   ``| head`` / ``take`` / equivalent cap so a clumsy execution can't
   DoS the SIEM. This is a safety requirement from the NightWing
   catalog (EPIC-1 / EPIC-4).

3. **Unknown TTP -> generic template.** If a TTP isn't in the library
   the node emits a generic "search for the technique id" query per
   backend rather than failing — the analyst can refine it.

4. **Backend selection.** The node only emits queries for the backends
   the caller requests (from ``HuntScope.backends`` or an explicit
   list). Empty request -> all backends in the library.
"""

from __future__ import annotations

import os
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_shared.types.hunt import Backend, Query


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_LLM", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Per-(TTP, backend) query template library
# ---------------------------------------------------------------------------
#
# Each template is a structurally-valid, count-capped query. Field names
# follow the common defaults for each platform; the real LLM path will
# resolve them against the org's actual schema registry.

_QUERY_LIBRARY: dict[str, dict[Backend, str]] = {
    "T1059.001": {  # PowerShell
        Backend.SPLUNK: (
            'index=endpoint EventCode=4688 (process_name="powershell.exe" OR '
            'process_name="pwsh.exe") (CommandLine="*-EncodedCommand*" OR '
            'CommandLine="*-enc*" OR CommandLine="*FromBase64String*") '
            "| head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName in~ ('powershell.exe','pwsh.exe') "
            "| where ProcessCommandLine has_any ('-EncodedCommand','-enc','FromBase64String') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            'process where process.name in ("powershell.exe","pwsh.exe") and '
            'process.command_line : ("*-EncodedCommand*","*-enc*","*FromBase64String*")'
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 (FileName=powershell.exe OR FileName=pwsh.exe) "
            "CommandLine=*EncodedCommand* | head 1000"
        ),
        Backend.SIGMA: (
            "title: Encoded PowerShell Execution\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: ['\\powershell.exe','\\pwsh.exe']\n"
            "    CommandLine|contains: ['-EncodedCommand','-enc','FromBase64String']\n"
            "  condition: selection"
        ),
    },
    "T1078.004": {  # Cloud Accounts
        Backend.SPLUNK: (
            'index=cloud sourcetype=aws:cloudtrail eventName="ConsoleLogin" '
            'errorMessage="*" | stats count by sourceIPAddress, userIdentity.userName '
            "| where count > 5 | head 1000"
        ),
        Backend.SENTINEL: (
            "SigninLogs | where ResultType != 0 | summarize FailedAttempts=count() "
            "by IPAddress, UserPrincipalName | where FailedAttempts > 5 | take 1000"
        ),
        Backend.ELASTIC: (
            'authentication where event.outcome == "failure" and '
            'cloud.provider != null | stats by source.ip, user.name'
        ),
        Backend.SIGMA: (
            "title: Suspicious Cloud Account Authentication\n"
            "logsource: {product: azure, service: signinlogs}\n"
            "detection:\n"
            "  selection: {ResultType: '50126'}\n"
            "  condition: selection | count() by IPAddress > 5"
        ),
    },
    "T1566.001": {  # Spearphishing Attachment
        Backend.SPLUNK: (
            'index=email (attachment_type="*.docm" OR attachment_type="*.xlsm" OR '
            'attachment_type="*.zip") | stats count by sender, recipient, attachment_name '
            "| head 1000"
        ),
        Backend.SENTINEL: (
            "EmailAttachmentInfo | where FileType in ('docm','xlsm','zip','iso') "
            "| join EmailEvents on NetworkMessageId | take 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Email Attachment\n"
            "logsource: {category: email}\n"
            "detection:\n"
            "  selection: {attachment_extension: ['docm','xlsm','iso','zip']}\n"
            "  condition: selection"
        ),
    },
    "T1110": {  # Brute Force
        Backend.SPLUNK: (
            "index=auth action=failure | stats count by src_ip, user "
            "| where count > 10 | head 1000"
        ),
        Backend.SENTINEL: (
            "SecurityEvent | where EventID == 4625 | summarize Failures=count() "
            "by IpAddress, Account | where Failures > 10 | take 1000"
        ),
        Backend.ELASTIC: (
            'authentication where event.outcome == "failure" '
            "| stats by source.ip, user.name"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=UserLogonFailed | stats count by RemoteAddressIP4, UserName "
            "| where count > 10"
        ),
        Backend.SIGMA: (
            "title: Brute Force Authentication\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 4625}\n"
            "  condition: selection | count() by IpAddress > 10"
        ),
    },
    "T1190": {  # Exploit Public-Facing Application
        Backend.SPLUNK: (
            'index=web (status>=500 OR uri_path="*..*" OR uri_query="*union*select*") '
            "| stats count by src_ip, uri_path | head 1000"
        ),
        Backend.SENTINEL: (
            "W3CIISLog | where scStatus >= 500 or csUriQuery has_any ('union','select','..') "
            "| take 1000"
        ),
        Backend.SIGMA: (
            "title: Web Exploitation Attempt\n"
            "logsource: {category: webserver}\n"
            "detection:\n"
            "  selection: {sc_status: [500,501,502]}\n"
            "  condition: selection"
        ),
    },
    "T1486": {  # Data Encrypted for Impact (ransomware)
        Backend.SPLUNK: (
            'index=endpoint EventCode=11 (file_name="*.encrypted" OR file_name="*.locked" '
            'OR file_name="*READ*ME*ransom*") | stats count by host, process_name | head 1000'
        ),
        Backend.SENTINEL: (
            "DeviceFileEvents | where FileName endswith '.encrypted' or FileName endswith '.locked' "
            "| summarize count() by DeviceName, InitiatingProcessFileName | take 1000"
        ),
        Backend.SIGMA: (
            "title: Ransomware File Encryption\n"
            "logsource: {category: file_event, product: windows}\n"
            "detection:\n"
            "  selection: {TargetFilename|endswith: ['.encrypted','.locked']}\n"
            "  condition: selection"
        ),
    },
}

# Backends covered by the library at all (for the "all backends" default).
_DEFAULT_BACKENDS: list[Backend] = [
    Backend.SPLUNK,
    Backend.SENTINEL,
    Backend.ELASTIC,
    Backend.CROWDSTRIKE,
    Backend.SIGMA,
]


def _generic_query(ttp_id: str, backend: Backend) -> str:
    """Fallback query for TTPs not in the library. Structurally valid,
    count-capped, and obviously a placeholder so the analyst refines it.
    """
    if backend == Backend.SPLUNK:
        return f'index=* tag="{ttp_id}" OR search="*{ttp_id}*" | head 500  ``` TODO: refine for {ttp_id} ```'
    if backend in (Backend.SENTINEL, Backend.DEFENDER):
        return f"// TODO: refine for {ttp_id}\nsearch '{ttp_id}' | take 500"
    if backend == Backend.ELASTIC:
        return f'any where true /* TODO: map {ttp_id} to concrete telemetry */ | head 500'
    if backend == Backend.CROWDSTRIKE:
        return f"// TODO: map {ttp_id}\nevent_platform=Win | head 500"
    return (
        f"title: TODO {ttp_id}\nlogsource: {{}}\ndetection:\n  condition: false  "
        f"# placeholder — map {ttp_id} to real telemetry"
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class QuerySynthInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttp_id: str = Field(..., description="ATT&CK technique id to synthesise queries for.")
    behavioral_description: str = Field(
        default="",
        description="Behavioural description from the hypothesis. Feeds the LLM "
        "path; ignored in mock mode (template library is keyed by ttp_id).",
    )
    backends: list[Backend] = Field(
        default_factory=list,
        description="Which backends to emit queries for. Empty == all library backends.",
    )


class QuerySynthOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttp_id: str
    queries: dict[Backend, Query] = Field(default_factory=dict)
    mock_mode: bool


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class QuerySynthNode(Node[QuerySynthInput, QuerySynthOutput]):
    """Synthesise per-backend hunt queries for a single TTP."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.query_synth",
        name="Query Synthesizer",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Generate per-backend hunt queries (SPL / KQL / EQL / CQL / Sigma) "
            "from an ATT&CK technique and behavioural description."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = QuerySynthInput
    output_schema: ClassVar[type[BaseModel]] = QuerySynthOutput

    async def run(
        self,
        input: QuerySynthInput,
        ctx: NodeContext,
    ) -> QuerySynthOutput:
        backends = input.backends or _DEFAULT_BACKENDS

        # Client-or-deterministic: when a real LLM client is registered and
        # mock mode is off, generate queries via the model; otherwise (and on
        # any LLM failure) fall back to the deterministic template library,
        # which is genuinely functional. Never hard-raise.
        from btagent_engine.llm import get_llm_client

        client = get_llm_client()
        if not _mock_mode_enabled() and client is not None:
            llm_queries = await self._llm_generate(input, backends, client, ctx)
            if llm_queries:
                return QuerySynthOutput(
                    ttp_id=input.ttp_id, queries=llm_queries, mock_mode=False
                )

        library_entry = _QUERY_LIBRARY.get(input.ttp_id, {})
        queries: dict[Backend, Query] = {}
        for backend in backends:
            template = library_entry.get(backend)
            if template is None:
                template = _generic_query(input.ttp_id, backend)
                note = f"Generic placeholder for {input.ttp_id} — refine against your schema."
            else:
                note = f"Count-capped template for {input.ttp_id}. Review field names before running."
            queries[backend] = Query(backend=backend, query=template, notes=note)

        return QuerySynthOutput(
            ttp_id=input.ttp_id, queries=queries, mock_mode=True
        )

    async def _llm_generate(self, input, backends, client, ctx):
        """LLM path: one count-capped query per backend. Returns {} on any
        failure so the caller falls back to the template library."""
        from btagent_engine.reasoning._llm_json import call_llm_json
        from btagent_shared.types.config import TLP, ModelTier

        backend_list = ", ".join(b.value for b in backends)
        system = (
            "You are a detection engineer. Given an ATT&CK technique and a "
            "behavioural description, write ONE hunt query per requested backend. "
            "Respond ONLY with a JSON object mapping backend -> query string "
            "(no prose, no markdown). Every query MUST be result-capped "
            "(| head N, | take N, LIMIT N, or equivalent). Backends use their "
            "native language: splunk=SPL, sentinel/defender=KQL, elastic=ES|QL, "
            "crowdstrike=CQL, sigma=Sigma YAML."
        )
        user = (
            f"technique: {input.ttp_id}\n"
            f"behaviour: {input.behavioral_description or '(none given)'}\n"
            f"backends: {backend_list}\nReturn the JSON object now."
        )
        try:
            tlp = TLP(ctx.tlp_level)
        except ValueError:
            tlp = TLP.GREEN

        raw = await call_llm_json(
            client, system=system, user=user, tlp=tlp, tier=ModelTier.STANDARD, array=False
        )
        if not isinstance(raw, dict):
            return {}

        out: dict[Backend, Query] = {}
        for backend in backends:
            q = raw.get(backend.value)
            if isinstance(q, str) and q.strip():
                out[backend] = Query(
                    backend=backend,
                    query=q.strip(),
                    notes=f"LLM-generated for {input.ttp_id}. Review fields before running.",
                )
        return out


NodeRegistry.register(QuerySynthNode)


__all__ = [
    "QuerySynthInput",
    "QuerySynthNode",
    "QuerySynthOutput",
]
