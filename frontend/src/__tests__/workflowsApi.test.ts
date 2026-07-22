/**
 * Unit tests for the workflows API client's run-version URL construction:
 * the background option must (and only must) append ?background=true.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

const post = vi.fn();

vi.mock("@/api/client", () => ({
  default: {
    post: (...a: unknown[]) => post(...a),
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

import { runVersion } from "@/api/workflows";

describe("runVersion", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    post.mockResolvedValue({ id: "wfrun_1", status: "running" });
  });

  it("posts to the plain run URL by default", async () => {
    await runVersion("wf_1", 2, { trigger_payload: { a: 1 } });
    expect(post).toHaveBeenCalledWith("/v1/workflows/wf_1/versions/2/run", {
      trigger_payload: { a: 1 },
    });
  });

  it("appends ?background=true when the background option is set", async () => {
    await runVersion("wf_1", 2, { trigger_payload: {} }, { background: true });
    expect(post).toHaveBeenCalledWith("/v1/workflows/wf_1/versions/2/run?background=true", {
      trigger_payload: {},
    });
  });

  it("background:false keeps the plain URL", async () => {
    await runVersion("wf_1", 2, {}, { background: false });
    expect(post).toHaveBeenCalledWith("/v1/workflows/wf_1/versions/2/run", {});
  });
});
