import { create } from "zustand";
import type { ChatMessage, HITLCheckpoint } from "@/types/investigation";
import { chatInvestigation, getInvestigationHistory } from "@/api/investigations";
import { getWSClient } from "@/api/ws";

interface AgentState {
  messages: ChatMessage[];
  pendingCheckpoints: HITLCheckpoint[];
  isStreaming: boolean;
  streamingContent: string;
  investigationId: string | null;
  isLoadingHistory: boolean;

  setInvestigation: (id: string) => void;
  loadHistory: (investigationId: string) => Promise<void>;
  sendMessage: (content: string) => Promise<void>;
  appendStreamChunk: (chunk: string) => void;
  finalizeStreamMessage: (messageId: string, content: string) => void;
  addAssistantMessage: (message: ChatMessage) => void;
  addCheckpoint: (checkpoint: HITLCheckpoint) => void;
  resolveCheckpoint: (checkpointId: string) => void;
  /**
   * Clear the streaming flag if a stream is in flight, without appending a
   * message. Used by terminal events (error / investigation complete) so the
   * chat input can never be left permanently disabled.
   */
  finalizeStreamIfActive: () => void;
  /**
   * Returns false when the decision could NOT be delivered (socket down), in
   * which case the checkpoint is deliberately left pending.
   */
  respondToCheckpoint: (
    checkpointId: string,
    approved: boolean,
    comment?: string,
  ) => boolean;
  clearMessages: () => void;
}

export const useAgentStore = create<AgentState>((set, get) => ({
  messages: [],
  pendingCheckpoints: [],
  isStreaming: false,
  streamingContent: "",
  investigationId: null,
  isLoadingHistory: false,

  setInvestigation: (id: string) => {
    set({
      investigationId: id,
      messages: [],
      pendingCheckpoints: [],
      isStreaming: false,
      streamingContent: "",
    });
  },

  loadHistory: async (investigationId: string) => {
    set({ isLoadingHistory: true });
    try {
      const history = await getInvestigationHistory(investigationId);
      set({ messages: history, isLoadingHistory: false });
    } catch {
      // History may not exist yet for new investigations
      set({ messages: [], isLoadingHistory: false });
    }
  },

  sendMessage: async (content: string) => {
    const { investigationId } = get();
    if (!investigationId) return;

    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}-user`,
      role: "user",
      content,
      timestamp: new Date().toISOString(),
    };

    // NOTE: `isStreaming` is deliberately NOT set until we know the message
    // actually left the browser. It is cleared by OUTPUT_COMPLETE / OUTPUT /
    // ERROR / INVESTIGATION_* handling in the workspace; setting it for a send
    // that silently failed left the chat input disabled until a page reload.
    set((state) => ({
      messages: [...state.messages, userMessage],
      streamingContent: "",
    }));

    try {
      // Try WebSocket first for real-time streaming
      const wsClient = getWSClient();
      const sentOverWs =
        wsClient.isConnected && wsClient.sendChat(investigationId, content);
      if (sentOverWs) {
        set({ isStreaming: true, streamingContent: "" });
      } else {
        // Fall back to REST
        const response = await chatInvestigation(investigationId, content);
        set((state) => ({
          messages: [...state.messages, response],
          isStreaming: false,
          streamingContent: "",
        }));
      }
    } catch {
      set((state) => ({
        messages: [
          ...state.messages,
          {
            id: `msg-${Date.now()}-error`,
            role: "system" as const,
            content: "Failed to send message. Please try again.",
            timestamp: new Date().toISOString(),
          },
        ],
        isStreaming: false,
        streamingContent: "",
      }));
    }
  },

  appendStreamChunk: (chunk: string) => {
    set((state) => ({
      streamingContent: state.streamingContent + chunk,
    }));
  },

  finalizeStreamMessage: (messageId: string, content: string) => {
    const finalMessage: ChatMessage = {
      id: messageId,
      role: "assistant",
      content,
      timestamp: new Date().toISOString(),
    };

    set((state) => ({
      messages: [...state.messages, finalMessage],
      isStreaming: false,
      streamingContent: "",
    }));
  },

  addAssistantMessage: (message: ChatMessage) => {
    set((state) => ({
      messages: [...state.messages, message],
    }));
  },

  addCheckpoint: (checkpoint: HITLCheckpoint) => {
    set((state) => ({
      pendingCheckpoints: [...state.pendingCheckpoints, checkpoint],
    }));
  },

  resolveCheckpoint: (checkpointId: string) => {
    set((state) => ({
      pendingCheckpoints: state.pendingCheckpoints.filter(
        (cp) => cp.id !== checkpointId,
      ),
    }));
  },

  finalizeStreamIfActive: () => {
    if (!get().isStreaming) return;
    set({ isStreaming: false, streamingContent: "" });
  },

  respondToCheckpoint: (
    checkpointId: string,
    approved: boolean,
    comment?: string,
  ): boolean => {
    const { investigationId } = get();
    if (!investigationId) return false;

    const wsClient = getWSClient();
    const sent = wsClient.sendHITLResponse(
      investigationId,
      checkpointId,
      approved,
      comment,
    );

    if (!sent) {
      // The decision never left the browser. Removing the card here (the old
      // behaviour) made an approve/reject of a containment action silently
      // evaporate — the analyst sees the card vanish and believes the action
      // was authorised. There is no REST fallback for HITL, so keep the card
      // pending and surface the failure instead.
      set((state) => ({
        messages: [
          ...state.messages,
          {
            id: `msg-${Date.now()}-hitl-error`,
            role: "system" as const,
            content:
              "Could not deliver your approval decision — the real-time connection is down. The checkpoint is still pending; please retry.",
            timestamp: new Date().toISOString(),
          },
        ],
      }));
      return false;
    }

    // Delivered — remove the card. The engine's HITL_RESPONSE / HITL_TIMEOUT
    // event also resolves it, so a double-resolve is a harmless no-op.
    get().resolveCheckpoint(checkpointId);
    return true;
  },

  clearMessages: () => {
    set({
      messages: [],
      pendingCheckpoints: [],
      isStreaming: false,
      streamingContent: "",
    });
  },
}));
