"""Every request body the API binds rejects fields it does not declare.

Pydantic v2 defaults to ``extra='ignore'``. A request model without
``extra="forbid"`` therefore accepts an unknown field, drops it, and returns
success — the caller cannot tell the difference between "you sent it and I
used it" and "you misspelled it and I ignored you".

That is the #586 failure mode (FastAPI discards an unknown *query* parameter
without a word) on a larger and more dangerous surface, because request bodies
carry the fields that govern classification:

    CreateInvestigationRequest(title="t", tlpp_level="red", sevrity="critical")
    -> severity=medium, tlp_level=green

A misspelled ``tlp_level`` creates the investigation at TLP:GREEN instead of
the RED that was asked for. Nothing raises, nothing logs, and the case is
routed to cloud LLMs it should never have reached. Four of the sixty-three
``*Request`` models under ``api/v1`` set ``extra="forbid"`` before this guard;
the rest were all one typo away from that.

``test_api_query_param_parity``'s docstring used to claim request bodies were
*not* exposed to this, "because Pydantic does reject unknown fields when
configured to". The conditional was carrying the whole claim and it was wrong
in practice — almost nothing was so configured. That sentence is corrected
there, and this file is what makes the corrected version true.

What is checked
---------------
Every class in ``backend/btagent_backend/api/v1/*.py`` whose name ends in
``Request`` and which subclasses ``BaseModel`` must declare
``extra="forbid"`` — directly, or by inheriting a base that does.

Nested models are covered too. The first version of this guard scanned the
AST for classes named ``*Request``, and named the gap that left: a field typed
as another ``BaseModel`` is only strict if *that* model is too, and a nested
model called ``FooPayload`` was invisible. It walked straight past
``HuntPlanIOC`` — reachable from ``HuntPlanRequest``, permissive, and carrying
the ``type``/``value`` of every indicator an ad-hoc hunt runs against. So the
scan now walks the live models' annotations from each request root, which
finds a nested model regardless of what it is called.

What is NOT checked, so a pass isn't read as more than it is
------------------------------------------------------------
* **Bodies that are not models.** A route taking ``dict[str, Any]`` accepts
  anything by construction; no model means nothing to tighten.
* **Response models.** Only inbound bodies are in scope — ``extra`` on a
  response shape has no bearing on what a caller can smuggle in.
* **Semantics.** A field that is declared, spelled right, and wrong for the
  situation is a different problem entirely.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import get_args

from pydantic import BaseModel

_REPO = Path(__file__).resolve().parents[2]
_API_DIR = _REPO / "backend" / "btagent_backend" / "api" / "v1"

#: ``"module.ClassName" -> why it may accept undeclared fields.``
#:
#: Ships empty. The bar is high because the failure mode is silence: an entry
#: here says "a caller may misspell a field on this model and get a 2xx".
#: "It has no security-relevant fields" is not a reason — the next field added
#: to it might, and nothing would re-open the question.
FORBID_EXEMPT: dict[str, str] = {}

# A scan this simple could match nothing and pass. Set below the real count at
# the time of writing (63) so ordinary additions do not trip it.
_MIN_REQUEST_MODELS = 45


@lru_cache(maxsize=1)
def _body_models() -> dict[str, bool]:
    """``{"ClassName": forbids_extras}`` for every model a request body can reach.

    Roots are the ``*Request`` classes declared under ``api/v1``; from each,
    field annotations are walked transitively so nested models are included
    under whatever name they happen to have. Imported rather than parsed —
    resolving ``list[HuntPlanIOC] | None`` by hand would be its own bug farm,
    and the reachability guard already imports the app.
    """
    import btagent_backend.api.v1 as v1

    found: dict[str, bool] = {}
    seen: set[type] = set()

    def _annotated_types(annotation: object) -> Iterator[object]:
        yield annotation
        for arg in get_args(annotation):
            yield from _annotated_types(arg)

    def _walk(model: type[BaseModel]) -> None:
        if model in seen:
            return
        seen.add(model)
        found[model.__name__] = model.model_config.get("extra") == "forbid"
        for field in model.model_fields.values():
            for candidate in _annotated_types(field.annotation):
                if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                    _walk(candidate)

    for module_info in pkgutil.iter_modules(v1.__path__):
        module = importlib.import_module(f"btagent_backend.api.v1.{module_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseModel)
                and obj.__name__.endswith("Request")
                and obj.__module__.startswith("btagent_backend")
            ):
                _walk(obj)
    return found


def _orphaned_docstrings() -> list[str]:
    """Classes whose docstring is no longer in docstring position.

    A string literal that is not the first statement is a no-op expression and
    the class silently has no ``__doc__``. Twenty-two classes ended up like
    this when ``extra="forbid"`` was inserted mechanically above the existing
    docstrings — the suite was green throughout, because nothing asserts a
    docstring. This is the cheap check that would have caught it.
    """
    out: list[str] = []
    for path in sorted(_API_DIR.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.ClassDef) or len(node.body) < 2:
                continue
            for stmt in node.body[1:]:
                if (
                    isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)
                ):
                    out.append(f"{path.name}:{stmt.lineno} {node.name}")
    return out


def test_the_scan_finds_a_realistic_number_of_models():
    """Guard the guard: an empty scan would make the check below vacuous."""
    models = _body_models()
    assert len(models) >= _MIN_REQUEST_MODELS, f"only found {len(models)} body-reachable models"


def test_the_scan_reads_forbid_correctly():
    """Pin one model end to end, so a parser returning junk cannot pass.

    ``CreateInvestigationRequest`` is the one whose silent drop of a misspelled
    ``tlp_level`` motivated this file, so it is the one worth pinning.
    """
    models = _body_models()
    assert models.get("CreateInvestigationRequest") is True
    # And the nested model the AST scan could not see.
    assert models.get("HuntPlanIOC") is True


def test_every_request_model_forbids_undeclared_fields():
    """The ratchet: a new request model must reject what it does not declare."""
    permissive = sorted(
        name
        for name, forbids in _body_models().items()
        if not forbids and name not in FORBID_EXEMPT
    )
    assert not permissive, (
        "These request models silently accept and drop undeclared fields:\n  "
        + "\n  ".join(permissive)
        + '\n\nAdd `model_config = ConfigDict(extra="forbid")`. Without it a '
        "caller who misspells a field gets a 2xx and the model's default — "
        "which for tlp_level means the case is created at GREEN instead of the "
        "RED that was asked for (#586's failure mode, on request bodies)."
    )


def test_exemption_list_only_holds_live_models():
    """The exemption list may only shrink."""
    models = _body_models()

    stale = sorted(set(FORBID_EXEMPT) - set(models))
    assert not stale, (
        f"FORBID_EXEMPT names models that no longer exist: {stale}. "
        "Remove them — a ratchet's exemption list may only shrink."
    )

    now_strict = sorted(name for name in FORBID_EXEMPT if models.get(name))
    assert not now_strict, (
        f"FORBID_EXEMPT names models that now forbid extras: {now_strict}. "
        "The exemption is obsolete; delete it."
    )


def test_no_class_has_an_orphaned_docstring():
    """A string literal below the first statement is dead, and costs the __doc__.

    Guards the mistake that produced it: inserting ``model_config`` above an
    existing class docstring demotes that docstring to a no-op expression. It
    happened to 22 classes at once, and every suite stayed green because
    nothing asserts a docstring.
    """
    orphaned = _orphaned_docstrings()
    assert not orphaned, (
        "These classes have a string literal that is not their docstring, so "
        "they have no __doc__:\n  "
        + "\n  ".join(orphaned)
        + "\n\nMove the docstring back to the first statement in the class body."
    )
