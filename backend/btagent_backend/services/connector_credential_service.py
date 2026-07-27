"""Connector credential-reference store (#100).

Persistence for the per-org binding between a connector and the
``${secret:...}`` reference that resolves its credential material. Two hard
invariants, both enforced here:

* **References only.** :func:`upsert_credential` refuses any value that isn't
  a single complete secret/env reference (``is_secret_reference``), so raw
  secret material can never land in the table.
* **Known connectors only.** The ``connector_name`` must match an installed
  connector (the catalog is the source of truth), so a binding can't point
  at a connector that doesn't exist.

Per the codebase convention nothing here commits — the route owns the single
commit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from btagent_shared.utils.ids import generate_id
from btagent_shared.utils.secrets import (
    SECRET_PATTERN,
    UnresolvedSecretError,
    is_secret_reference,
    resolve_secret,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_connector import ConnectorCredentialRow
from btagent_backend.services import connector_catalog

logger = logging.getLogger("btagent.services.connector_credential")


class InvalidCredentialReference(ValueError):
    """The supplied value isn't a single ``${secret:...}`` / ``${env:...}`` reference."""


class UnknownConnector(LookupError):
    """The connector_name doesn't match any installed connector."""


def _require_known_connector(connector_name: str) -> None:
    if connector_catalog.get_manifest(connector_name) is None:
        raise UnknownConnector(f"Connector '{connector_name}' is not installed")


async def upsert_credential(
    db: AsyncSession,
    *,
    org_id: str,
    connector_name: str,
    secret_ref: str,
    label: str = "",
    actor_id: str = "",
) -> ConnectorCredentialRow:
    """Create or update an org's credential binding for a connector.

    Raises :class:`UnknownConnector` for an unknown connector and
    :class:`InvalidCredentialReference` when ``secret_ref`` is not a single
    complete reference (never storing raw material). Not committed.
    """
    _require_known_connector(connector_name)
    if not is_secret_reference(secret_ref):
        raise InvalidCredentialReference(
            "secret_ref must be a single ${secret:...} / ${env:VAR} reference — "
            "raw secret material is never stored; put it in Vault/AWS/env and "
            "reference it here."
        )

    existing = await get_credential(db, org_id=org_id, connector_name=connector_name)
    if existing is not None:
        existing.secret_ref = secret_ref.strip()
        existing.label = label[:200]
        existing.updated_by = actor_id
        await db.flush()
        return existing

    row = ConnectorCredentialRow(
        id=generate_id("ccred"),
        org_id=org_id,
        connector_name=connector_name,
        secret_ref=secret_ref.strip(),
        label=label[:200],
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(row)
    await db.flush()
    return row


async def get_credential(
    db: AsyncSession, *, org_id: str, connector_name: str
) -> ConnectorCredentialRow | None:
    """Org-scoped lookup of a connector's credential binding."""
    return (
        await db.execute(
            select(ConnectorCredentialRow).where(
                ConnectorCredentialRow.org_id == org_id,
                ConnectorCredentialRow.connector_name == connector_name,
            )
        )
    ).scalar_one_or_none()


async def list_credentials(db: AsyncSession, *, org_id: str) -> list[ConnectorCredentialRow]:
    """All credential bindings for an org, connector-name ordered."""
    rows = (
        (
            await db.execute(
                select(ConnectorCredentialRow)
                .where(ConnectorCredentialRow.org_id == org_id)
                .order_by(ConnectorCredentialRow.connector_name)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def delete_credential(db: AsyncSession, *, org_id: str, connector_name: str) -> bool:
    """Delete an org's binding for a connector. Returns True when one existed."""
    row = await get_credential(db, org_id=org_id, connector_name=connector_name)
    if row is None:
        return False
    await db.delete(row)
    await db.flush()
    return True


# --------------------------------------------------------------------------- #
# Reference verification (#101)
# --------------------------------------------------------------------------- #

# The resolver emits this shape in non-prod when a vault/aws reference has no
# client wired in and the env fallback also missed. It is a *placeholder*, not
# a credential — a naive truthiness check would report a broken Vault binding
# as healthy in every non-prod deployment, which is exactly the failure this
# endpoint exists to catch.
_UNRESOLVED_PREFIX = "<unresolved:"


@dataclass(frozen=True)
class CredentialVerification:
    """Outcome of resolving a stored credential reference.

    Deliberately carries **no** secret material — not the resolved value, and
    not its length either, since a length is an entropy hint an operator
    never needs and an attacker sometimes does. Only whether resolution
    succeeded, which provider it targeted, and a human-readable reason.
    """

    connector_name: str
    bound: bool
    secret_ref: str
    provider: str
    resolved: bool
    detail: str


def _provider_of(secret_ref: str) -> str:
    """Which backend a reference targets — for 'go fix it *there*' guidance."""
    match = SECRET_PATTERN.fullmatch(secret_ref.strip())
    if match is None:
        return "unknown"
    if match.group("provider"):
        return str(match.group("provider"))
    if match.group("env"):
        return "env"
    if match.group("legacy"):
        return "env"
    return "unknown"


async def verify_credential(
    db: AsyncSession, *, org_id: str, connector_name: str
) -> CredentialVerification:
    """Check that an org's stored credential reference actually resolves.

    This is the honest half of a "test connection": it verifies the
    *reference*, not the vendor endpoint (which needs live credentials the
    deployment may not have). That is the failure mode worth catching early —
    a typo'd ``${env:SPLUNK_TOKN}`` resolves to the empty string and every
    downstream consumer accepts it silently, so the binding looks fine right
    up until a hunt returns nothing.

    Only the **already-stored** reference for ``org_id`` is resolved. The
    caller cannot pass a reference in: an endpoint that resolved arbitrary
    user-supplied references would be a probe for the server's environment
    and Vault namespace, reporting hit/miss for any path an admin cared to
    guess. Verifying only what is already bound keeps it a diagnostic.

    Raises :class:`UnknownConnector` for a connector that isn't installed.
    Never raises for a resolution failure — that *is* the result.
    """
    _require_known_connector(connector_name)

    row = await get_credential(db, org_id=org_id, connector_name=connector_name)
    if row is None:
        return CredentialVerification(
            connector_name=connector_name,
            bound=False,
            secret_ref="",
            provider="none",
            resolved=False,
            detail="No credential reference is bound for this connector.",
        )

    secret_ref = row.secret_ref or ""
    provider = _provider_of(secret_ref)

    try:
        value = resolve_secret(secret_ref)
    except UnresolvedSecretError as exc:
        # prod turns an unresolvable vault/aws reference into a hard error.
        return CredentialVerification(
            connector_name=connector_name,
            bound=True,
            secret_ref=secret_ref,
            provider=provider,
            resolved=False,
            detail=str(exc),
        )
    except Exception:
        # A misbehaving provider client must not 500 a diagnostic endpoint.
        logger.exception(
            "Credential verification failed for connector %s (org=%s)", connector_name, org_id
        )
        return CredentialVerification(
            connector_name=connector_name,
            bound=True,
            secret_ref=secret_ref,
            provider=provider,
            resolved=False,
            detail="The secret provider raised an error while resolving this reference.",
        )

    if value.startswith(_UNRESOLVED_PREFIX):
        return CredentialVerification(
            connector_name=connector_name,
            bound=True,
            secret_ref=secret_ref,
            provider=provider,
            resolved=False,
            detail=(
                f"No {provider} client is configured and the environment fallback is unset, "
                "so this reference resolves to a placeholder rather than a credential."
            ),
        )

    if not value.strip():
        return CredentialVerification(
            connector_name=connector_name,
            bound=True,
            secret_ref=secret_ref,
            provider=provider,
            resolved=False,
            detail=f"The reference resolves to an empty value — check it exists in {provider}.",
        )

    return CredentialVerification(
        connector_name=connector_name,
        bound=True,
        secret_ref=secret_ref,
        provider=provider,
        resolved=True,
        detail=f"Reference resolves to a non-empty value via {provider}.",
    )
