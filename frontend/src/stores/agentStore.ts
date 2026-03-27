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
  respondToCheckpoint: (
    checkpointId: string,
    approved: boolean,
    comment?: string,
  ) => void;
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

    set((state) => ({
      messages: [...state.messages, userMessage],
      isStreaming: true,
      streamingContent: "",
    }));

    try {
      // Try WebSocket first for real-time streaming
      const wsClient = getWSClient();
      if (wsClient.isConnected) {
        wsClient.sendChat(investigationId, content);
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

  respondToCheckpoint: (
    checkpointId: string,
    approved: boolean,
    comment?: string,
  ) => {
    const { investigationId } = get();
    if (!investigationId) return;

    const wsClient = getWSClient();
    wsClient.sendHITLResponse(investigationId, checkpointId, approved, comment);

    // Optimistically remove the checkpoint
    get().resolveCheckpoint(checkpointId);
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
