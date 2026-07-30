# Hunt packs: external Sigma corpora and the `bt huntpack` CLI (#112)

A *hunt pack* is a versioned bundle of Sigma rules the scheduled hunt runner
transpiles to your connected SIEM/EDR backends and executes on a cadence. Two
kinds exist, and the runner treats them identically:

| Kind | Where it lives | Who provides it |
| --- | --- | --- |
| **builtin** | `engine/btagent_engine/hunting/packs/<name>/` (ships in the image) | BTagent |
| **installed** | `<BTAGENT_HUNT_PACK_INSTALL_DIR>/<org_id>/<pack_id>/` | you, via `bt huntpack install` |

Enable state for both lives in the existing `org_hunt_packs` table — one row per
`(org_id, pack_id)`. Installing a corpus adds **no** new tables.

## Installing an external corpus

Point the CLI at a local directory of Sigma rules. SigmaHQ's nested layout
(`rules/<product>/<category>/*.yml`, sibling trees such as
`rules-threat-hunting/`) and a flat directory of `*.yml` both work;
`deprecated/`, `unsupported/`, `tests/` and dot-directories are pruned.

```bash
git clone https://github.com/SigmaHQ/sigma ~/sigma        # you fetch it, not us
bt huntpack install ~/sigma --name "SigmaHQ core" --version 2026.07
```

Nothing is downloaded by BTagent — at install time or at test time. Fetching a
catalog is an operator action, deliberately outside the product's network
surface.

### What the importer does with a rule it cannot use

A community corpus of ~1000 rules always contains some this platform cannot
run. The import **skips those with a reason and installs the rest** — it never
aborts:

| Stage | Meaning |
| --- | --- |
| `parse` | not valid YAML / not a mapping / no `title` / fails the rule contract |
| `transpile` | parses, but **no** requested backend can express it (e.g. legacy `\| count() by … > N` aggregations) |
| `duplicate` | its Sigma `id` was already claimed by an earlier file (merged trees) |

A rule that transpiles on *at least one* backend is installed; the runner
already records per-backend errors at run time, so a Windows-only rule is not
discarded because the Falcon pipeline rejects it.

Every skip is printed by the CLI and persisted in `install_report.json` inside
the pack directory, alongside a per-backend coverage summary. `pack.yaml` also
records, per rule, which backends it transpiled to (`transpiles`) and the error
for those it didn't (`transpile_errors`).

## Commands

```bash
bt huntpack list                            # catalog + enable state for this org
bt huntpack install <path> [options]        # import an external Sigma corpus
bt huntpack enable  <pack-id>
bt huntpack disable <pack-id>
```

Useful `install` options: `--pack-id` (install key; defaults to a slug of
`--name`), `--version`, `--backend` (repeatable; defaults to all four),
`--skip-transpile-check` (parse-only, no pySigma cost), `--max-rules`,
`--no-enable`, `--overwrite`, `--json`.

### Org scoping

There is no request and therefore no JWT, so the target org resolves as:

1. `--org <id>`
2. `$BTAGENT_ORG_ID`
3. the default org (`org_default`)

**Every command prints which org it acted on and where that came from.** An
installed pack is org-scoped on disk as well as in the database: it appears in
that org's catalog only, and another org cannot enable it.

The CLI talks to the database directly, so it carries DB-level trust and does
not re-implement the HTTP API's RBAC gate (`huntpack:manage`), which protects
API callers rather than someone who already holds the database URL. Writes are
recorded with `updated_by="cli:<user>"`.

## Configuration

| Setting | Env var | Default |
| --- | --- | --- |
| Install root | `BTAGENT_HUNT_PACK_INSTALL_DIR` | `./data/hunt_packs` |

In a container this must point at a persistent volume — the pack directory *is*
the rule store; the database only records which packs are enabled.

## Transpile coverage

`engine/tests/test_hunting_corpus.py` measures the per-backend transpile rate
over a small **vendored** SigmaHQ-shaped corpus
(`engine/tests/fixtures/sigmahq_sample/`) and asserts per-backend floors plus
the plan's ≥80% aggregate bar, so coverage cannot regress silently. Measured at
the time of writing: splunk / elastic / crowdstrike 90.9%, sentinel 81.8%
(no Advanced Hunting table mapping for the DNS log source).

## Not included

* Downloading the full SigmaHQ catalog at build or run time.
* A live count-only executor for the imported rules (blocked on #100).
