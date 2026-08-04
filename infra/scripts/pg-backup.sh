#!/usr/bin/env bash
#
# PostgreSQL backup for the Docker Compose stack.
#
# The Helm chart ships its own CronJob (infra/helm/btagent/templates/
# backup-cronjob.yaml); this is the compose-side equivalent, with the same
# properties, so a compose operator is not left hand-rolling the fragile
# one-liner the docs used to suggest:
#
#     pg_dump ... | gzip > /backups/btagent-$(date +%F).sql.gz
#
# That line has two failure modes that both end with an operator discovering,
# mid-incident, that they have no backup:
#
#   1. **A truncated dump looks valid.** If pg_dump dies partway (disk full,
#      connection reset, OOM-killed), gzip still writes a well-formed archive
#      of the partial output. Without `pipefail` the pipeline's exit status is
#      gzip's, so cron records success. The file has a plausible name and a
#      plausible size, and restores a plausible-looking fraction of the
#      database.
#   2. **`-mtime +30` retention deletes good backups.** Age-based pruning does
#      not care whether anything replaced what it removes. Thirty-one days of
#      silently failing backups and the retention job has deleted the last
#      good one.
#
# So: dump to a `.partial` name, *verify it*, and only then rename. Retention
# keeps the newest N complete dumps by count, and never counts or removes a
# `.partial`.
#
# Custom format (-Fc) rather than plain SQL + gzip. It is already compressed,
# it restores with pg_restore (so the backup and the documented restore
# command actually match — they did not before), and it can be verified.
#
# On verification: `pg_restore --list` is the obvious check and it is **not
# good enough**. A custom-format archive keeps its table of contents at the
# head, so `--list` reads the TOC and stops — a dump truncated anywhere in the
# data blocks lists cleanly. Measured, not assumed: a dump cut to 90% of its
# length still passed `--list`. `pg_restore -f /dev/null` decodes every block
# instead, and rejects both the 90% and 50% truncations while accepting an
# intact archive. It costs a second full read of the dump, which is cheap next
# to having produced it.
#
# Usage:
#     BTAGENT_DATABASE_URL=postgresql://user:pw@host:5432/db \
#     BACKUP_DIR=/backups BACKUP_KEEP_LAST=7 ./infra/scripts/pg-backup.sh
#
# Restore the newest dump with:
#     pg_restore --clean --if-exists -d "$BTAGENT_DATABASE_URL" \
#       "$(ls -1t /backups/btagent-*.dump | head -1)"

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP_LAST="${BACKUP_KEEP_LAST:-7}"

if [ "${BACKUP_KEEP_LAST}" -lt 2 ]; then
  # Keeping one means the only good backup is deleted the moment a new one
  # lands — and if that new one is the first of a broken run, there is now
  # nothing to restore from.
  echo "pg-backup: BACKUP_KEEP_LAST must be >= 2 (got ${BACKUP_KEEP_LAST})" >&2
  exit 2
fi

# SQLAlchemy DSNs carry a driver suffix (postgresql+asyncpg://) that libpq
# does not understand. Strip it so the same variable the app uses works here —
# pointing the backup at a different database than the one serving traffic is
# a failure nobody notices until a restore.
DSN="${BTAGENT_DATABASE_URL:-}"
DSN="$(printf '%s' "${DSN}" | sed 's#^postgresql+[a-z0-9]*://#postgresql://#')"

if [ -z "${DSN}" ]; then
  echo "pg-backup: BTAGENT_DATABASE_URL is empty — refusing to write an empty backup" >&2
  exit 2
fi

mkdir -p "${BACKUP_DIR}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="${BACKUP_DIR}/btagent-${STAMP}.dump"

# Dump to .partial so an interrupted run never leaves a file that looks like a
# finished backup. A leftover .partial is a visible symptom, not a silent one.
if ! pg_dump --format=custom --no-owner --no-privileges --file="${DEST}.partial" "${DSN}"; then
  echo "pg-backup: pg_dump failed; leaving ${DEST}.partial for inspection" >&2
  exit 1
fi

# Verify before promoting. pg_dump exiting 0 is necessary, not sufficient.
# `-f /dev/null` decodes the whole archive (see the note above on why
# `--list` is not enough) and fails on a dump that could not be restored.
if ! pg_restore -f /dev/null "${DEST}.partial" >/dev/null 2>&1; then
  echo "pg-backup: ${DEST}.partial failed verification; not promoting it" >&2
  exit 1
fi

mv "${DEST}.partial" "${DEST}"
echo "pg-backup: wrote ${DEST} ($(wc -c <"${DEST}") bytes)"

# Retention by count over *complete* dumps only. The glob cannot match a
# .partial, so a failed run neither counts toward the limit nor gets pruned.
# shellcheck disable=SC2012  # names are ours and contain no newlines
ls -1t "${BACKUP_DIR}"/btagent-*.dump 2>/dev/null \
  | tail -n +"$((BACKUP_KEEP_LAST + 1))" \
  | xargs -r rm -f

REMAINING="$(ls -1 "${BACKUP_DIR}"/btagent-*.dump 2>/dev/null | wc -l)"
echo "pg-backup: retention keeps ${BACKUP_KEEP_LAST}; ${REMAINING} dump(s) present"
