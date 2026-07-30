/**
 * CustomPacksPanel (#112 slice 2) — the upload half of the HuntPacks screen.
 *  1. Lists uploaded packs with rule counts; empty state otherwise.
 *  2. Delete is two-step (arm, then confirm).
 *  3. Analyst (below huntpack:manage) sees the list read-only — no upload
 *     input, no delete buttons.
 *  4. A server 422 (the engine loader's complaint) surfaces verbatim.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const mockList = vi.fn();
const mockUpload = vi.fn();
const mockDelete = vi.fn();

vi.mock("@/api/hunt", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/hunt")>()),
  listCustomPacks: (...a: unknown[]) => mockList(...a),
  uploadCustomPack: (...a: unknown[]) => mockUpload(...a),
  deleteCustomPack: (...a: unknown[]) => mockDelete(...a),
}));

let mockRole = "senior_analyst";
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel: (s: { user: { role: string } | null }) => unknown) =>
    sel({ user: { role: mockRole } }),
}));

import { CustomPacksPanel } from "@/components/hunts/CustomPacksPanel";

const PACK = {
  id: "ocp_1",
  pack_id: "hpack_abc",
  name: "Org Custom Pack",
  version: "1.0.0",
  description: "Uploaded in tests.",
  rule_count: 3,
  created_by: "usr_1",
  created_at: "2026-07-30T00:00:00Z",
  updated_at: "2026-07-30T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  mockRole = "senior_analyst";
  mockList.mockResolvedValue({ items: [PACK], total: 1 });
});

describe("CustomPacksPanel", () => {
  it("lists uploaded packs with rule counts", async () => {
    render(<CustomPacksPanel />);
    expect(await screen.findByTestId("custom-pack-ocp_1")).toBeInTheDocument();
    expect(screen.getByTestId("custom-pack-rules")).toHaveTextContent("3 rules");
    expect(screen.getByTestId("custom-pack-form")).toBeInTheDocument();
  });

  it("shows the empty state when nothing is uploaded", async () => {
    mockList.mockResolvedValue({ items: [], total: 0 });
    render(<CustomPacksPanel />);
    expect(await screen.findByTestId("custom-packs-empty")).toBeInTheDocument();
  });

  it("delete is two-step: first click arms, second deletes", async () => {
    mockDelete.mockResolvedValue(undefined);
    render(<CustomPacksPanel />);
    const btn = await screen.findByTestId("custom-pack-delete-ocp_1");

    fireEvent.click(btn);
    expect(btn).toHaveTextContent("Confirm delete");
    expect(mockDelete).not.toHaveBeenCalled();

    fireEvent.click(btn);
    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith("ocp_1"));
  });

  it("analyst sees the list read-only", async () => {
    mockRole = "analyst";
    render(<CustomPacksPanel />);
    expect(await screen.findByTestId("custom-pack-ocp_1")).toBeInTheDocument();
    expect(screen.queryByTestId("custom-pack-form")).not.toBeInTheDocument();
    expect(screen.queryByTestId("custom-pack-delete-ocp_1")).not.toBeInTheDocument();
  });

  it("surfaces the loader's 422 verbatim on a bad upload", async () => {
    const { ApiError } = await import("@/api/client");
    mockUpload.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", { detail: "rule file 'r.yml' has no 'title'" }),
    );
    render(<CustomPacksPanel />);
    const input = (await screen.findByTestId("custom-pack-files")) as HTMLInputElement;

    const manifest = new File(["name: p\nversion: '1'\n"], "pack.yaml", {
      type: "text/yaml",
    });
    const rule = new File(["detection: {}"], "r.yml", { type: "text/yaml" });
    fireEvent.change(input, { target: { files: [manifest, rule] } });

    expect(await screen.findByTestId("custom-packs-error")).toHaveTextContent(
      "rule file 'r.yml' has no 'title'",
    );
  });
});
