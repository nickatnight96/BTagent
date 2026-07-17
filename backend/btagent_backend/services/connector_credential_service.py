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

from btagent_shared.utils.ids import generate_id
from btagent_shared.utils.secrets import is_secret_reference
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_connector import ConnectorCredentialRow
from btagent_backend.services import connector_catalog


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
