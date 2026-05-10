"""4-layer context-window reduction cascade.

Reasoning Nodes (anything that pushes a transcript at an LLM) feed
their conversation through :func:`apply_cascade` before dispatch so it
fits in the model's context window. The cascade applies four layers in
order, stopping as soon as the running estimate drops under budget:

1. **Externalise** -- large tool/result payloads are hashed and
   replaced with an ``artifact:<sha256>`` reference. Full content is
   returned alongside so the artifact store can persist it.
2. **Compress** -- still-too-big payloads get JSON-aware sampling or
   text truncation.
3. **Prune** -- sliding-window: keep first-N + last-N messages, drop
   the middle and leave a marker.
4. **Summarize** -- final fallback. The cascade is summariser-agnostic;
   the caller passes a sync or async ``summarizer`` callable that turns
   the prefix into a single message.

Ported from ``btagent_agents.context.cascade`` (the original spec) and
restructured to remove the agents-package coupling: token estimation
is now a small builtin (no ``btagent_agents.context.budget`` import)
and the summariser is injected rather than baked in.
"""

from btagent_engine.context.artifacts import (
    ArtifactRef,
    content_byte_length,
    make_artifact_ref,
)
from btagent_engine.context.cascade import (
    COMPRESS_THRESHOLD,
    EXTERNALIZE_THRESHOLD,
    PRUNE_KEEP_FIRST,
    PRUNE_KEEP_LAST,
    CascadeResult,
    ContextLayer,
    apply_cascade,
    estimate_message_tokens,
    estimate_tokens,
    layer0_externalize,
    layer1_compress,
    layer2_prune,
    layer3_summarize,
)

__all__ = [
    "COMPRESS_THRESHOLD",
    "EXTERNALIZE_THRESHOLD",
    "PRUNE_KEEP_FIRST",
    "PRUNE_KEEP_LAST",
    "ArtifactRef",
    "CascadeResult",
    "ContextLayer",
    "apply_cascade",
    "content_byte_length",
    "estimate_message_tokens",
    "estimate_tokens",
    "layer0_externalize",
    "layer1_compress",
    "layer2_prune",
    "layer3_summarize",
    "make_artifact_ref",
]
