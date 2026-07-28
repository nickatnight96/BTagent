/**
 * Tagging a MITRE technique from the IOC detail panel (#473 ratchet).
 *
 * `POST /mitre/tag` (senior analyst+) had no UI, and the panel's "MITRE
 * ATT&CK Techniques" section read from a field no backend code populated —
 * write path unreachable, read path fictional. This covers the new form:
 * senior-gated, typo-rejecting, and refreshing the IOC afterwards so the
 * server-resolved technique name appears rather than a locally-spliced id.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const tagTechnique = vi.fn();

vi.mock("@/api/mitre", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/mitre")>()),
  tagTechnique: (...a: unknown[]) => tagTechnique(...a),
}));

import { IOCDetailPanel } from "@/components/iocs/IOCDetailPanel";
import { useIOCStore } from "@/stores/iocStore";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { ApiError } from "@/api/client";
import type { IOC } from "@/types/ioc";

const BASE_IOC = {
  id: "ioc_1",
  type: "ip",
  value: "198.51.100.7",
  confidence: 0.9,
  mitre_tags: [],
} as unknown as IOC;

function setUp(role: UserRole | null, ioc: IOC = BASE_IOC) {
  useAuthStore.setState({
    user: role ? { id: "usr_1", username: "t", role } : null,
  });
  useIOCStore.setState({
    selectedIOC: ioc,
    isEnriching: false,
    fetchIOC: vi.fn().mockResolvedValue(undefined),
  });
  return render(<IOCDetailPanel onClose={() => {}} />);
}

describe("IOCDetailPanel MITRE tagging", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    tagTechnique.mockResolvedValue({ id: "mtag_1" });
  });

  it("hides the form from plain analysts — their every click would 403", () => {
    setUp(UserRole.ANALYST);
    expect(screen.queryByTestId("ioc-detail-tag-form")).toBeNull();
  });

  it("keeps the section invisible for analysts when there are no tags", () => {
    // Pre-slice behaviour preserved: nothing renders for a viewer who can
    // neither see tags (none exist) nor create one.
    setUp(UserRole.ANALYST);
    expect(screen.queryByTestId("ioc-detail-mitre-section")).toBeNull();
  });

  it("shows the section to a senior analyst even before the first tag", () => {
    setUp(UserRole.SENIOR_ANALYST);
    expect(screen.getByTestId("ioc-detail-mitre-section")).toBeTruthy();
    expect(screen.getByTestId("ioc-detail-tag-form")).toBeTruthy();
  });

  it("rejects a malformed technique id before calling the server", async () => {
    setUp(UserRole.SENIOR_ANALYST);
    fireEvent.change(screen.getByTestId("ioc-detail-tag-input"), {
      target: { value: "not-a-technique" },
    });
    fireEvent.click(screen.getByTestId("ioc-detail-tag-submit"));

    expect((await screen.findByTestId("ioc-detail-tag-error")).textContent).toContain(
      "T1059",
    );
    expect(tagTechnique).not.toHaveBeenCalled();
  });

  it("tags the IOC and refreshes it so the server-resolved name renders", async () => {
    setUp(UserRole.SENIOR_ANALYST);
    fireEvent.change(screen.getByTestId("ioc-detail-tag-input"), {
      target: { value: "t1059.001" },
    });
    fireEvent.click(screen.getByTestId("ioc-detail-tag-submit"));

    await waitFor(() =>
      expect(tagTechnique).toHaveBeenCalledWith({
        entity_type: "ioc",
        entity_id: "ioc_1",
        // Lower-case input is normalised — Txxxx ids are upper-case.
        technique_id: "T1059.001",
      }),
    );
    const { fetchIOC } = useIOCStore.getState();
    await waitFor(() => expect(fetchIOC).toHaveBeenCalledWith("ioc_1"));
  });

  it("surfaces the server's refusal verbatim", async () => {
    // 404 here means "entity not yours / technique unknown" — the detail
    // names which, and flattening it would hide the difference.
    tagTechnique.mockRejectedValue(
      new ApiError(404, "Not Found", { detail: "Technique not found: T9999" }),
    );
    setUp(UserRole.SENIOR_ANALYST);
    fireEvent.change(screen.getByTestId("ioc-detail-tag-input"), {
      target: { value: "T9999" },
    });
    fireEvent.click(screen.getByTestId("ioc-detail-tag-submit"));

    expect((await screen.findByTestId("ioc-detail-tag-error")).textContent).toContain(
      "Technique not found",
    );
  });

  it("renders existing tags for any role, with the form only for seniors", () => {
    const tagged = {
      ...BASE_IOC,
      mitre_tags: [
        { technique_id: "T1566", technique_name: "Phishing", tactic: "initial-access" },
      ],
    } as unknown as IOC;
    setUp(UserRole.ANALYST, tagged);
    expect(screen.getByTestId("ioc-detail-mitre-tag-T1566-link")).toBeTruthy();
    expect(screen.queryByTestId("ioc-detail-tag-form")).toBeNull();
  });
});
