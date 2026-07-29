/**
 * EvidenceDetail — pivot-question rendering (#435).
 *
 * The identity detectors attach curated `pivot_questions` to finding
 * evidence; the detail block must render them as a "Suggested pivots" list
 * and stay silent when they're absent (older findings recorded before the
 * questions existed).
 */
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { EvidenceDetail } from "@/components/identity/IdentityHuntsPage";
import type { IdentityFindingEvidence } from "@/types/identity_hunt";

describe("EvidenceDetail pivot questions", () => {
  it("renders the suggested-pivots list when evidence carries questions", () => {
    const evidence: IdentityFindingEvidence = {
      principal_id: "alice@corp.example.com",
      pivot_questions: [
        "Which other principals authenticated from the same ASNs in the replay window?",
        "What did the replayed session access after the second ASN appeared (mail, files, admin APIs)?",
      ],
    };
    render(<EvidenceDetail evidence={evidence} />);

    expect(screen.getByTestId("identity-pivot-questions")).toBeInTheDocument();
    expect(screen.getByText("Suggested pivots")).toBeInTheDocument();
    expect(
      screen.getByText(/Which other principals authenticated from the same ASNs/),
    ).toBeInTheDocument();
    // The key/value evidence rows still render alongside.
    expect(screen.getByText("alice@corp.example.com")).toBeInTheDocument();
  });

  it("omits the block entirely when there are no questions", () => {
    const evidence: IdentityFindingEvidence = { principal_id: "bob@corp.example.com" };
    render(<EvidenceDetail evidence={evidence} />);
    expect(screen.queryByTestId("identity-pivot-questions")).not.toBeInTheDocument();
  });

  it("ignores non-string entries defensively", () => {
    const evidence = {
      principal_id: "carol@corp.example.com",
      pivot_questions: [42, "", "Real question?"] as unknown as string[],
    } satisfies IdentityFindingEvidence;
    render(<EvidenceDetail evidence={evidence} />);
    const block = screen.getByTestId("identity-pivot-questions");
    expect(block.querySelectorAll("li")).toHaveLength(1);
    expect(screen.getByText("Real question?")).toBeInTheDocument();
  });
});
