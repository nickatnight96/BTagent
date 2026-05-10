# btagent-engine — workflow engine

This is the workflow runtime that lives underneath the BTagent
agent / API / canvas surfaces. Every workflow node — triggers,
integrations (Splunk, VirusTotal, …), reasoning steps, decisions,
outputs — is a `Node` subclass executed by a `Runner` with a
middleware chain wrapped around it.

The engine is deliberately standalone-shippable: its only sibling-
package import is `btagent-shared` (Pydantic types, IDs, security
helpers). Nothing here depends on `btagent-agents`, `btagent-backend`,
or the React frontend. That is the spec — the engine must be
embeddable in other security tools per the redesign plan.

## Status — Sprint 1 spike

What's in: the foundation. Everything else is queued for Sprints 2
and 3.

* `Node` ABC with Pydantic input/output schemas + class-level metadata.
* `NodeContext` — frozen, `extra="forbid"` — for per-run state.
* `NodeRegistry` — explicit-registration map of node id → class.
* `Middleware` + `Runner` — composition wrapper around `Node.run`,
  ordered like ASGI / express (before in registration order, after
  in reverse).
* One reference integration node: `GreyNoiseLookupIPNode`, with
  embedded mock fixtures and a deterministic "not seen" fall-through.
* 24 tests: ABC contract, registry collision behaviour, runner
  middleware ordering, end-to-end through the reference node.

What's out (Sprint 2):

* Move `agents/btagent_agents/playbook/compiler.py` →
  `engine/btagent_engine/compiler/`. Wrap each playbook step type
  (`action`, `decision`, `parallel`, `hitl_gate`) as a Node.
* Move the remaining 8 MCP integrations as Node subclasses.
* Move the existing hooks (HITL, EventEmitter, Classification / TLP
  egress, EvidenceChain, ScopeEnforcement, PromptBudget) as
  Middleware subclasses. The TLP egress middleware in particular is
  already centralised in `shared/btagent_shared/security/tlp.py` —
  the middleware just calls into it.
* Live API path for every connector (currently `NotImplementedError`
  outside mock mode), wired through the credential vault.

What's out (Sprint 3):

* Re-wire `agents/btagent_agents/orchestrator/graph.py` to use the
  engine instead of the hand-coded subgraphs.
* Convert `Triage`, `Query`, `Enrich`, `Knowledge` into seeded
  workflow templates, not Python functions.
* Drop the now-duplicated code from `agents/btagent_agents/`.

## Adding a Node

1. Pick a stable id of the form
   `<category>.<vendor_or_subject>.<operation>`. Stable means: don't
   change it after the node ships, ever — workflow files reference it.
2. Define the input + output schemas as Pydantic models.
3. Subclass `Node`, set `meta`, `input_schema`, `output_schema`,
   implement `async run`.
4. Decorate the class with `@NodeRegistry.register` so the canvas
   palette picks it up.
5. Add a test under `engine/tests/` that drives the node through the
   `Runner` (so you also exercise the input-validation path).

```python
from pydantic import BaseModel, Field
from btagent_engine import (
    Node, NodeCategory, NodeContext, NodeMeta, NodeRegistry,
)


class FooLookupInput(BaseModel):
    target: str = Field(..., description="What to look up")


class FooLookupOutput(BaseModel):
    found: bool


@NodeRegistry.register
class FooLookupNode(Node[FooLookupInput, FooLookupOutput]):
    meta = NodeMeta(
        id="integration.foo.lookup",
        name="Foo: Lookup",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="...",
    )
    input_schema = FooLookupInput
    output_schema = FooLookupOutput

    async def run(self, input: FooLookupInput, ctx: NodeContext) -> FooLookupOutput:
        ...
```

## Middleware ordering

`Runner.execute` walks the middleware chain like a request-response
cycle:

```
mw[0].before  →  mw[1].before  →  node.run  →  mw[1].after  →  mw[0].after
```

On error from `node.run` (or from any `after_run`), `on_error` runs
in reverse order and the Runner re-raises. Middleware cannot swallow
errors — recovery is the workflow compiler's job, not the
middleware's.

Recommended ordering for the production middleware stack (Sprint 2):

```python
Runner([
    EvidenceChainMiddleware(),     # outermost: records every input/output
    TLPEgressMiddleware(),         # blocks RED data before it reaches downstream
    HITLMiddleware(),              # may pause the run before node.run
    PromptBudgetMiddleware(),      # enforces $ / token caps for reasoning nodes
    EventEmitterMiddleware(),      # innermost: streams to WebSocket
])
```

## Why no DI container, no plugin discovery hooks, no ABC for Middleware

The temptation with workflow engines is to build a lot of
infrastructure (DI, lifecycle hooks, sub-class-discovery magic, a
custom event bus). Resisted on purpose:

* **No DI container.** The Runner takes a list of middlewares; nodes
  resolve their own dependencies via constructor args. If we need
  shared state (Redis client, HTTP pool), we'll pass it through
  `NodeContext.metadata` or via constructor injection on the node
  class — cheaper than a framework.
* **No auto-discovery of node subclasses.** The Registry is a
  hand-curated dict updated by `@register`. Magic discovery makes
  test-only nodes leak into production. If discovery becomes
  necessary later, a single `import_module` over a list of allowed
  packages does it explicitly.
* **`Middleware` is not an ABC.** Subclasses opt into whichever hooks
  they need; no required methods. An ABC would force every middleware
  to implement all three hooks for no real benefit.
