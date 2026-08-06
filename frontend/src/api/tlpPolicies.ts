import api from "./client";

export type TLPPolicyAction = "allow" | "deny" | "downgrade_then_allow";
export type TLP = "red" | "amber_strict" | "amber" | "green" | "white";
// Defined in `types/containment.ts` so the shared-enum parity guard compares
// it against the Python `EgressKind`; a hand-written copy here is how
// `report_export` came to be missing from the policy picker.
import { EGRESS_KINDS, type EgressKind } from "@/types/containment";

export { EGRESS_KINDS };
export type { EgressKind };

export interface TLPPolicy {
  id: string;
  org_id: string;
  action: TLPPolicyAction;
  egress_kinds: string[];
  applies_to_tlp: TLP[];
  downgrade_to: TLP | null;
  approver_id: string;
  rationale: string;
  valid_until: string | null;
  created_at: string;
}

export interface CreateTLPPolicy {
  action: TLPPolicyAction;
  egress_kinds?: string[];
  applies_to_tlp?: TLP[];
  downgrade_to?: TLP | null;
  rationale?: string;
  valid_until?: string | null;
}

export interface PolicyDecision {
  allowed: boolean;
  effective_tlp: TLP;
  action: TLPPolicyAction;
  matched_policy_id: string | null;
  reason: string;
}

export async function listTLPPolicies(): Promise<TLPPolicy[]> {
  return api.get<TLPPolicy[]>("/v1/tlp-policies");
}

export async function createTLPPolicy(body: CreateTLPPolicy): Promise<TLPPolicy> {
  return api.post<TLPPolicy>("/v1/tlp-policies", body);
}

export async function deleteTLPPolicy(id: string): Promise<void> {
  await api.delete(`/v1/tlp-policies/${id}`);
}

export async function evaluateTLPPolicy(
  tlp: TLP,
  egressKind: string,
): Promise<PolicyDecision> {
  return api.post<PolicyDecision>("/v1/tlp-policies/evaluate", {
    tlp,
    egress_kind: egressKind,
  });
}
