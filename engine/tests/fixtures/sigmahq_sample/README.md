# Vendored SigmaHQ-style sample corpus (#112)

A **committed**, deliberately small stand-in for a real SigmaHQ checkout, used
by `engine/tests/test_hunting_corpus.py` to measure per-backend transpile
coverage and to pin the importer's skip behaviour.

Vendored on purpose: the test suite does **zero network egress**
(`backend/tests/test_zero_egress.py`), so nothing is downloaded at test time.
Downloading the full ~1000-rule catalog at build/run time is deferred.

Layout mirrors the upstream repository — nested `rules/<product>/<category>/`,
a `rules-threat-hunting/` tree, and a `deprecated/` graveyard that the importer
prunes.

| File | Why it is here |
| --- | --- |
| `rules/**` (9 rules) | Representative, *valid* detections across process_creation, registry_set, Windows Security channel, Linux, and DNS log sources — the coverage denominator. |
| `rules-threat-hunting/**` | Proves the walker picks up sibling rule trees, not just `rules/`. |
| `proc_creation_win_broken_yaml.yml` | Unparseable YAML → skipped at the `parse` stage. |
| `proc_creation_win_missing_title.yml` | Valid YAML, no `title` → skipped at the `parse` stage. |
| `proc_creation_win_pipe_aggregation.yml` | Legacy `\| count() by … > N` syntax no backend can express → skipped at the `transpile` stage. |
| `proc_creation_win_certutil_encode_copy.yml` | Re-uses an earlier rule's Sigma `id` → skipped as a `duplicate`. |
| `deprecated/proc_creation_win_retired_rule.yml` | Must never be imported (pruned directory). |

The rule content is authored for this fixture in canonical SigmaHQ format; it
is not a copy of any upstream rule file.
