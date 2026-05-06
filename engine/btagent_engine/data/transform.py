"""TransformNode -- generic dict-to-dict shape bridge.

All schemas in the engine are ``extra=forbid``, which is great for
catching typos but lousy for plumbing data between Nodes whose
input/output shapes don't line up. Without a transform node a workflow
author has to write Python glue (or worse, a one-off Node) to rename
fields, drop unwanted keys, or seed static values.

The TransformNode applies a list of declarative rules in order to a
copy of the input payload and returns the rewritten dict. Supported
rules (one key per rule dict):

* ``{"rename": "src -> dst"}`` -- move ``src`` to ``dst``. ``src``
  missing is silently a no-op (matches "best-effort plumbing"
  intent); overwriting ``dst`` is allowed.
* ``{"drop": "field"}`` -- delete ``field``. Missing is a no-op.
* ``{"set": {"field": value, ...}}`` -- assign one or more
  fields to literal values; overwrites if present.
* ``{"keep_only": ["a", "b", ...]}`` -- discard every key not in
  the list.

Unknown rule keys raise ``ValueError`` -- silently ignoring would let
typos rot a workflow without warning.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

_KNOWN_RULE_KEYS = {"rename", "drop", "set", "keep_only"}


class TransformInput(BaseModel):
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Input dict to rewrite. Not mutated; the node operates on a copy.",
    )
    rules: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Ordered list of rules. Each rule is a single-key dict; "
        "supported keys: 'rename', 'drop', 'set', 'keep_only'.",
    )


class TransformOutput(BaseModel):
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Rewritten dict after applying rules in declaration order.",
    )


def _apply_rename(payload: dict[str, Any], spec: Any) -> None:
    if not isinstance(spec, str) or "->" not in spec:
        raise ValueError(
            f"'rename' rule expects a 'src -> dst' string, got {spec!r}"
        )
    src, _, dst = spec.partition("->")
    src = src.strip()
    dst = dst.strip()
    if not src or not dst:
        raise ValueError(
            f"'rename' rule requires non-empty source and destination, got {spec!r}"
        )
    if src in payload:
        payload[dst] = payload.pop(src)


def _apply_drop(payload: dict[str, Any], spec: Any) -> None:
    if not isinstance(spec, str):
        raise ValueError(f"'drop' rule expects a field name string, got {spec!r}")
    payload.pop(spec, None)


def _apply_set(payload: dict[str, Any], spec: Any) -> None:
    if not isinstance(spec, dict):
        raise ValueError(f"'set' rule expects a dict of field->value, got {spec!r}")
    for k, v in spec.items():
        if not isinstance(k, str):
            raise ValueError(f"'set' rule keys must be strings, got {k!r}")
        payload[k] = v


def _apply_keep_only(payload: dict[str, Any], spec: Any) -> None:
    if not isinstance(spec, list) or not all(isinstance(k, str) for k in spec):
        raise ValueError(
            f"'keep_only' rule expects a list of field-name strings, got {spec!r}"
        )
    keep = set(spec)
    for k in list(payload.keys()):
        if k not in keep:
            del payload[k]


@NodeRegistry.register
class TransformNode(Node[TransformInput, TransformOutput]):
    """Apply rename / drop / set / keep_only rules to a payload dict."""

    meta = NodeMeta(
        id="data.transform",
        name="Data: Transform",
        version="0.1.0",
        category=NodeCategory.DATA,
        description="Generic shape-bridge that rewrites a dict payload via an "
        "ordered list of rename / drop / set / keep_only rules. Used to plumb "
        "data between Nodes whose extra=forbid schemas would otherwise refuse "
        "the handoff.",
    )
    input_schema = TransformInput
    output_schema = TransformOutput

    async def run(
        self,
        input: TransformInput,
        ctx: NodeContext,
    ) -> TransformOutput:
        # Operate on a shallow copy so the caller's dict is not mutated.
        payload: dict[str, Any] = dict(input.payload)

        for index, rule in enumerate(input.rules):
            if not isinstance(rule, dict) or len(rule) != 1:
                raise ValueError(
                    f"Rule #{index} must be a single-key dict, got {rule!r}"
                )
            (key,) = rule.keys()
            if key not in _KNOWN_RULE_KEYS:
                raise ValueError(
                    f"Rule #{index} uses unknown key {key!r}; "
                    f"supported keys: {sorted(_KNOWN_RULE_KEYS)}"
                )
            spec = rule[key]
            if key == "rename":
                _apply_rename(payload, spec)
            elif key == "drop":
                _apply_drop(payload, spec)
            elif key == "set":
                _apply_set(payload, spec)
            elif key == "keep_only":
                _apply_keep_only(payload, spec)

        return TransformOutput(payload=payload)
