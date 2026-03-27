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

import os
import re
from functools import lru_cache

SECRET_PATTERN = re.compile(
    r"\$\{(?:secret:(?P<provider>vault|aws|keyring):(?P<path>[^}#]+)(?:#(?P<field>[^}]+))?|env:(?P<env>[^}]+)|(?P<legacy>[A-Z_][A-Z0-9_]*))\}"
)


def resolve_secret(value: str) -> str:
    """Resolve secret references in a string value.

    For Phase 1, only env and legacy patterns are implemented.
    Vault and AWS providers return placeholders until configured.
    """

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
            # Placeholder — real implementation in production
            env_fallback = path.upper().replace("/", "_").replace("-", "_")
            return os.environ.get(env_fallback, f"<unresolved:{provider}:{path}>")

        return match.group(0)

    return SECRET_PATTERN.sub(_replace, value)


@lru_cache(maxsize=1000)
def resolve_secret_cached(value: str) -> str:
    """Cached version of resolve_secret. 5-min TTL managed externally."""
    return resolve_secret(value)
