/**
 * CloudContainmentModal (#117 Phase C review UI).
 *
 * The gates live server-side; what the modal owns is honest *presentation* of
 * a double-gated decision: partial selection must be reflected in the accept
 * payload, a role below incident commander must see why it cannot decide,
 * and executed/denied outcomes must render with their audit trail.
 */
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { CloudContainmentModal } from "@/components/cloud/CloudContainmentModal";
import type { CloudContainmentProposal } from "@/types/cloud_hunt";

function proposal(over: Partial<CloudContainmentProposal> = {}): CloudContainmentProposal {
  return {
    actions: [
      {
        id: "cca_1",
        action_type: "revoke_role",
        provider: "aws",
        target: "arn:aws:iam::123456789012:role/finance-admin",
        source_finding_ids: ["hf_1"],
        status: "proposed",
        audit_id: null,
      },
      {
        id: "cca_2",
        action_type: "freeze_access_key",
        provider: "aws",
        target: "AKIAEXAMPLEKEY",
        source_finding_ids: ["hf_2"],
        status: "proposed",
        audit_id: null,
      },
    ],
    rationale: "STS chaining into the finance-admin role",
    status: "proposed",
    decided_by: null,
    decided_at: null,
    decision_rationale: "",
    ...over,
  };
}

const noop = () => {};

describe("CloudContainmentModal", () => {
  it("accepts with only the selected action ids and the rationale", () => {
    const onAccept = vi.fn();
    render(
      <CloudContainmentModal
        proposal={proposal()}
        canDecide
        isMutating={false}
        error={null}
        onAccept={onAccept}
        onReject={noop}
        onDismiss={noop}
      />,
    );
    // Deselect the access-key action — partial accept.
    fireEvent.click(screen.getByTestId("cloud-containment-select-cca_2"));
    fireEvent.change(screen.getByTestId("cloud-containment-rationale"), {
      target: { value: "revoke the pivot, keep the key for forensics" },
    });
    fireEvent.click(screen.getByTestId("cloud-containment-accept"));
    expect(onAccept).toHaveBeenCalledWith(
      ["cca_1"],
      "revoke the pivot, keep the key for forensics",
    );
  });

  it("disables accept when nothing is selected", () => {
    render(
      <CloudContainmentModal
        proposal={proposal()}
        canDecide
        isMutating={false}
        error={null}
        onAccept={noop}
        onReject={noop}
        onDismiss={noop}
      />,
    );
    fireEvent.click(screen.getByTestId("cloud-containment-select-cca_1"));
    fireEvent.click(screen.getByTestId("cloud-containment-select-cca_2"));
    expect(screen.getByTestId("cloud-containment-accept")).toBeDisabled();
  });

  it("shows the incident-commander requirement and no decision buttons below the role", () => {
    render(
      <CloudContainmentModal
        proposal={proposal()}
        canDecide={false}
        isMutating={false}
        error={null}
        onAccept={noop}
        onReject={noop}
        onDismiss={noop}
      />,
    );
    expect(screen.getByText(/incident commander/)).toBeInTheDocument();
    expect(screen.queryByTestId("cloud-containment-accept")).not.toBeInTheDocument();
    expect(screen.queryByTestId("cloud-containment-reject")).not.toBeInTheDocument();
    // Reading is allowed; deciding is not — dismiss stays available.
    expect(screen.getByTestId("cloud-containment-dismiss")).toBeInTheDocument();
  });

  it("renders executed and denied outcomes with their audit ids", () => {
    const decided = proposal({
      status: "accepted",
      actions: [
        {
          id: "cca_1",
          action_type: "revoke_role",
          provider: "aws",
          target: "arn:aws:iam::123456789012:role/finance-admin",
          source_finding_ids: [],
          status: "executed",
          audit_id: "aud_exec_1",
        },
        {
          id: "cca_2",
          action_type: "freeze_access_key",
          provider: "aws",
          target: "AKIAEXAMPLEKEY",
          source_finding_ids: [],
          status: "denied",
          audit_id: "aud_deny_2",
        },
      ],
    });
    render(
      <CloudContainmentModal
        proposal={decided}
        canDecide
        isMutating={false}
        error={null}
        onAccept={noop}
        onReject={noop}
        onDismiss={noop}
      />,
    );
    expect(screen.getByTestId("cloud-containment-decided")).toHaveTextContent(
      /Proposal accepted/,
    );
    expect(screen.getByTestId("cloud-containment-status-cca_1")).toHaveTextContent(
      /executed · audit aud_exec_1/,
    );
    expect(screen.getByTestId("cloud-containment-status-cca_2")).toHaveTextContent(
      /denied · audit aud_deny_2/,
    );
    // Decided proposals expose no further decision affordances.
    expect(screen.queryByTestId("cloud-containment-accept")).not.toBeInTheDocument();
  });

  it("surfaces a decision error verbatim", () => {
    render(
      <CloudContainmentModal
        proposal={proposal()}
        canDecide
        isMutating={false}
        error="Safelisted principal refused: break-glass role"
        onAccept={noop}
        onReject={noop}
        onDismiss={noop}
      />,
    );
    expect(screen.getByTestId("cloud-containment-error")).toHaveTextContent(/Safelisted/);
  });
});
