# Packaging out-of-tree workflow nodes (#101)

BTagent's workflow canvas, connector catalog, and executor all resolve nodes
through one registry (`btagent_engine.node.NodeRegistry`). Community node
packages join that registry **without forking the engine**: they ship as
normal Python distributions that declare their `Node` subclasses under the
`btagent.nodes` entry-point group.

## Writing a node package

A minimal package:

```
acme-btagent-nodes/
├── pyproject.toml
└── acme_btagent_nodes/
    ├── __init__.py
    └── lookup.py          # defines AcmeLookupNode(Node[...])
```

The node subclasses `btagent_engine.node.Node` exactly like a builtin: a
frozen `NodeMeta` (stable `id` — it is part of the workflow file format, never
change it once shipped), `input_schema` / `output_schema` Pydantic models, and
an async `run`. Namespace external ids (e.g. `external.acme.lookup`) so they
can never collide with builtin ids.

Declare one entry point per node class:

```toml
# pyproject.toml
[project]
name = "acme-btagent-nodes"
version = "1.0.0"
dependencies = ["btagent-engine"]

[project.entry-points."btagent.nodes"]
acme_lookup = "acme_btagent_nodes.lookup:AcmeLookupNode"
```

Each entry point must resolve to the `Node` subclass itself — not a module,
not an instance, not a factory.

## Enabling packages on a deployment

Installation alone is **not** enough — loading an entry point executes
third-party code, so the operator must allowlist each trusted distribution
explicitly:

```bash
pip install acme-btagent-nodes
export BTAGENT_EXTERNAL_NODE_PACKAGES="acme-btagent-nodes"   # comma-separated
```

The backend loads allowlisted packages at the same bootstrap point where the
builtin node tiers register (`workflow_run_service`), so external nodes appear
in the canvas palette and the `GET /connectors` catalog like any builtin.
Matching is PEP 503-normalised (`Acme_Nodes` == `acme-nodes`). There is
deliberately no "load everything" wildcard, and the default (unset/empty) loads
nothing.

## Failure containment

A broken package cannot take the engine down: each entry point loads and
validates independently, and failures — import errors, objects that are not
`Node` subclasses, id collisions with already-registered nodes — are recorded
in the loader's report and logged as warnings while the remaining entries
still load. Check backend logs for `btagent.node.external` on startup when a
node you expect is missing from the palette.

## Governance notes

* External **integration**-category nodes run under the same middleware chain
  as builtins (HITL, ConnectorPolicy, classification) — the executor wires
  middleware per run, not per node origin. Note the manifest semantics,
  though: `ConnectorPolicyMiddleware` treats a *missing* `ConnectorManifest`
  as benign (default policy — no HITL requirement, no TLP egress check, a
  logged warning). So an external integration node is only as gated as the
  manifest it ships. Before allowlisting a package that performs egress or
  actions, verify it declares a manifest with the HITL/TLP posture you
  expect.
* Review the package source before allowlisting it. The allowlist is a
  trust decision, not a sandbox: allowlisted code runs with the backend's
  privileges.
