"""``bt`` — BTagent operator CLI (#112).

The first console-script entrypoint in the repo
(``bt = btagent_backend.cli.main:main``). Commands are thin shells over the
*existing* service layer — no second implementation of anything — and every one
of them is org-scoped: see :mod:`btagent_backend.cli.huntpack`.

Deliberately empty of re-exports: a name like ``main`` here would shadow the
:mod:`btagent_backend.cli.main` submodule for ``from ... import main``.
"""

__all__: list[str] = []
