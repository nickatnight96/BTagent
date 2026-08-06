/**
 * Containment vocabularies shared with the backend.
 *
 * Lives under `types/` rather than beside the client in `api/containment.ts`
 * so `backend/tests/test_shared_enum_ts_parity.py` compares it against the
 * Python `SafelistEntryType` on every run. That guard only scans this
 * directory, and this union is exactly the kind it exists for: `principal`
 * was a valid, enforced entry kind that the TypeScript type did not name, so
 * the settings dropdown could not offer it and cloud IAM principals (#117)
 * were unreachable despite the service supporting them end to end.
 */

/** Mirrors `SafelistEntryType` in shared/btagent_shared/types/enums.py. */
export type SafelistEntryType = "ip" | "domain" | "principal";

/** Human labels for the safelist entry kinds, for pickers and tables. */
export const SAFELIST_ENTRY_TYPE_LABELS: Record<SafelistEntryType, string> = {
  ip: "IP",
  domain: "Domain",
  principal: "Principal",
};
