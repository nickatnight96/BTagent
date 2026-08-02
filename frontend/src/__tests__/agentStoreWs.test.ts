/**
 * agentStore ↔ WebSocket behaviour.
 *
 * Two confirmed defects are pinned here:
 *
 *  - HITL: `respondToCheckpoint` used to remove the checkpoint card
 *    unconditionally, immediately after a fire-and-forget send. With the
 *    payload landing at the frame's top level (dropped by the server) or the
 *    socket simply being down, an analyst's approve/reject of a CONTAINMENT
 *    action vanished from the UI while never reaching the engine — and there
 *    is no REST fallback for HITL. The card must survive a failed send.
 *
 *  - Streaming: `sendMessage` set `isStreaming: true` unconditionally, and
 *    only a `message_complete` event (which no backend ever emitted) cleared
 *    it — so the chat input stayed disabled until a page reload.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

const sendChat = vi.fn();
const sendHITLResponse = vi.fn();
let isConnected = true;

vi.mock("@/api/ws", () => ({
  getWSClient: () => ({
    get isConnected() {
      return isConnected;
    },
    sendChat: (...a: unknown[]) => sendChat(...a) as boolean,
    sendHITLResponse: (...a: unknown[]) => sendHITLResponse(...a) as boolean,
  }),
}));

const chatInvestigation = vi.fn();
vi.mock("@/api/investigations", () => ({
  chatInvestigation: (...a: unknown[]) => chatInvestigation(...a),
  getInvestigationHistory: vi.fn(),
}));

import { useAgentStore } from "@/stores/agentStore";

const CHECKPOINT = {
  id: "cp_1",
  investigation_id: "inv_1",
  prompt: "Isolate host WKSTN-42?",
  timestamp: "2026-07-31T00:00:00Z",
  timeout_seconds: 300,
};

beforeEach(() => {
  sendChat.mockReset().mockReturnValue(true);
  sendHITLResponse.mockReset().mockReturnValue(true);
  chatInvestigation.mockReset();
  isConnected = true;
  useAgentStore.setState({
    messages: [],
    pendingCheckpoints: [],
    isStreaming: false,
    streamingContent: "",
    investigationId: "inv_1",
    isLoadingHistory: false,
  });
});

describe("agentStore — HITL checkpoint response", () => {
  it("resolves the checkpoint only when the decision was actually sent", () => {
    useAgentStore.getState().addCheckpoint(CHECKPOINT);
    expect(useAgentStore.getState().pendingCheckpoints).toHaveLength(1);

    const ok = useAgentStore
      .getState()
      .respondToCheckpoint("cp_1", true, "verified");

    expect(ok).toBe(true);
    expect(sendHITLResponse).toHaveBeenCalledWith(
      "inv_1",
      "cp_1",
      true,
      "verified",
    );
    expect(useAgentStore.getState().pendingCheckpoints).toHaveLength(0);
  });

  it("KEEPS the checkpoint pending when the send failed, and says so", () => {
    sendHITLResponse.mockReturnValue(false);
    useAgentStore.getState().addCheckpoint(CHECKPOINT);

    const ok = useAgentStore.getState().respondToCheckpoint("cp_1", false);

    expect(ok).toBe(false);
    // The card must NOT disappear — a vanished card reads as "approved".
    expect(useAgentStore.getState().pendingCheckpoints).toHaveLength(1);
    const messages = useAgentStore.getState().messages;
    const last = messages[messages.length - 1];
    expect(last?.role).toBe("system");
    expect(last?.content).toMatch(/still pending/i);
  });

  it("is a no-op without an active investigation", () => {
    useAgentStore.setState({ investigationId: null });
    expect(useAgentStore.getState().respondToCheckpoint("cp_1", true)).toBe(
      false,
    );
    expect(sendHITLResponse).not.toHaveBeenCalled();
  });
});

describe("agentStore — chat streaming flag", () => {
  it("marks streaming only after the message actually left over the socket", async () => {
    await useAgentStore.getState().sendMessage("what happened?");

    expect(sendChat).toHaveBeenCalledWith("inv_1", "what happened?");
    expect(useAgentStore.getState().isStreaming).toBe(true);
    expect(chatInvestigation).not.toHaveBeenCalled();
  });

  it("falls back to REST (and does not strand the input) when the socket is down", async () => {
    isConnected = false;
    chatInvestigation.mockResolvedValue({
      id: "msg_1",
      role: "assistant",
      content: "here you go",
      timestamp: "2026-07-31T00:00:00Z",
    });

    await useAgentStore.getState().sendMessage("what happened?");

    expect(chatInvestigation).toHaveBeenCalledWith("inv_1", "what happened?");
    expect(useAgentStore.getState().isStreaming).toBe(false);
  });

  it("falls back to REST when the socket reports open but the send fails", async () => {
    sendChat.mockReturnValue(false);
    chatInvestigation.mockResolvedValue({
      id: "msg_1",
      role: "assistant",
      content: "here you go",
      timestamp: "2026-07-31T00:00:00Z",
    });

    await useAgentStore.getState().sendMessage("what happened?");

    expect(chatInvestigation).toHaveBeenCalled();
    expect(useAgentStore.getState().isStreaming).toBe(false);
  });

  it("finalizeStreamIfActive clears a stranded stream without inventing a message", () => {
    useAgentStore.setState({ isStreaming: true, streamingContent: "partial" });

    useAgentStore.getState().finalizeStreamIfActive();

    expect(useAgentStore.getState().isStreaming).toBe(false);
    expect(useAgentStore.getState().streamingContent).toBe("");
    expect(useAgentStore.getState().messages).toHaveLength(0);
  });
});
