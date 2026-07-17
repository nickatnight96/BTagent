"""Secret reference resolver supporting multiple providers.

Patterns:
    ${secret:vault:path/to/secret}       → HashiCorp Vault KV v2
    ${secret:vault:path/to/secret#field} → Vault with JSON field extraction
    ${secret:aws:secret-name}            → AWS Secrets Manager
    ${secret:aws:secret-name#field}      → AWS SM with field extraction
    ${secret:keyring:key-name}           → OS keyring (dev mode)
    ${env:VAR_NAME}                      → Environment variable
    ${VAR_NAME}                          → Legacy env variable pattern
"""

import logging
import os
import re
from functools import lru_cache

logger = logging.getLogger("btagent.shared.secrets")

SECRET_PATTERN = re.compile(
    r"\$\{(?:secret:(?P<provider>vault|aws|keyring):(?P<path>[^}#]+)(?:#(?P<field>[^}]+))?|env:(?P<env>[^}]+)|(?P<legacy>[A-Z_][A-Z0-9_]*))\}"
)


class UnresolvedSecretError(RuntimeError):
    """Raised when a ``${secret:vault:...}`` / ``${secret:aws:...}`` reference
    can't be resolved AND we're in an environment that should never silently
    fall through to a `<unresolved:...>` literal (prod).

    The vault/aws code paths historically returned a placeholder string when
    no real client was wired in, which is fine for dev but silently shipped
    broken config to prod. ``BTAGENT_ENV=prod`` now turns the silent fallback
    into a hard failure.
    """


def resolve_secret(value: str) -> str:
    """Resolve secret references in a string value.

    For Phase 1, only env and legacy patterns are implemented.
    Vault and AWS providers return placeholders in non-prod when no client is
    wired in; in ``BTAGENT_ENV=prod`` an unresolvable vault/aws reference
    raises :class:`UnresolvedSecretError` instead of silently producing a
    ``<unresolved:...>`` literal that downstream config would happily accept.
    """

    is_prod = os.environ.get("BTAGENT_ENV", "").lower() == "prod"

    def _replace(match: re.Match) -> str:
        provider = match.group("provider")
        path = match.group("path")
        field = match.group("field")
        env_var = match.group("env")
        legacy = match.group("legacy")

        if env_var:
            return os.environ.get(env_var, "")

        if legacy:
            return os.environ.get(legacy, "")

        if provider == "keyring":
            # OS keyring for dev mode
            try:
                import keyring

                result = keyring.get_password("btagent", path)
                return result or ""
            except ImportError:
                return os.environ.get(path.upper().replace("-", "_"), "")

        if provider in ("vault", "aws"):
            env_fallback = path.upper().replace("/", "_").replace("-", "_")
            resolved = os.environ.get(env_fallback)
            if resolved is not None:
                return resolved
            # No real client wired in; the env fallback also missed. In prod
            # this is a fatal config error — fail loudly rather than ship
            # ``<unresolved:...>`` to whatever downstream uses the value.
            if is_prod:
                raise UnresolvedSecretError(
                    f"Cannot resolve ${{secret:{provider}:{path}}} in prod: "
                    f"no {provider.upper()} client configured and env fallback "
                    f"`{env_fallback}` is not set."
                )
            # Non-prod: keep the historical placeholder so smoke tests and
            # local dev keep limping along, but emit a warning so the gap
            # is visible in CI logs.
            logger.warning(
                "secret resolver: no client for provider=%s; env fallback %r not set; "
                "emitting placeholder for non-prod env",
                provider,
                env_fallback,
            )
            return f"<unresolved:{provider}:{path}>"

        return match.group(0)

    return SECRET_PATTERN.sub(_replace, value)


@lru_cache(maxsize=1000)
def resolve_secret_cached(value: str) -> str:
    """Cached version of resolve_secret. 5-min TTL managed externally."""
    return resolve_secret(value)


def is_secret_reference(value: str) -> bool:
    """True when ``value`` is exactly one secret/env reference token.

    Used by the credential-reference store (#100) to refuse raw secret
    material: only a single complete ``${secret:...}`` / ``${env:VAR}`` /
    ``${VAR}`` reference is a valid credential *reference*. A string that
    merely contains a reference amid other text, or is raw material, returns
    ``False`` — the actual secret must live in the resolver's backend
    (Vault / AWS SM / env), never in the reference store.
    """
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    match = SECRET_PATTERN.fullmatch(stripped)
    return match is not None
