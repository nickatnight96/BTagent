import { create } from "zustand";
import type { Node, Edge } from "@xyflow/react";
import { StepType, TriggerType, OnFailure } from "@/types/playbook";
import type {
  Playbook,
  PlaybookExecution,
  PlaybookStep,
  CreatePlaybookRequest,
} from "@/types/playbook";
import {
  listPlaybooks,
  getPlaybook,
  createPlaybook as apiCreatePlaybook,
  updatePlaybook as apiUpdatePlaybook,
  executePlaybook as apiExecutePlaybook,
  getExecution,
} from "@/api/playbooks";

interface PlaybookState {
  // List state
  playbooks: Playbook[];
  isLoading: boolean;
  error: string | null;

  // Current playbook (for editing)
  currentPlaybook: Playbook | null;

  // Builder state (React Flow)
  builderNodes: Node[];
  builderEdges: Edge[];
  selectedNodeId: string | null;

  // Execution state
  executionState: PlaybookExecution | null;

  // List actions
  fetchPlaybooks: (params?: { search?: string; is_active?: boolean }) => Promise<void>;

  // CRUD actions
  createPlaybook: (data: CreatePlaybookRequest) => Promise<Playbook>;
  savePlaybook: (id: string) => Promise<void>;
  setCurrentPlaybook: (playbook: Playbook | null) => void;
  loadPlaybook: (id: string) => Promise<void>;

  // Builder actions
  setBuilderNodes: (nodes: Node[]) => void;
  setBuilderEdges: (edges: Edge[]) => void;
  addNode: (node: Node) => void;
  updateNode: (id: string, data: Record<string, unknown>) => void;
  removeNode: (id: string) => void;
  connectNodes: (edge: Edge) => void;
  removeEdge: (id: string) => void;
  setSelectedNode: (id: string | null) => void;
  clearBuilder: () => void;

  // Execution actions
  executePlaybook: (id: string, investigationId?: string) => Promise<void>;
  fetchExecution: (executionId: string) => Promise<void>;
  setExecutionState: (execution: PlaybookExecution | null) => void;

  clearError: () => void;
}

export const usePlaybookStore = create<PlaybookState>((set, get) => ({
  playbooks: [],
  isLoading: false,
  error: null,
  currentPlaybook: null,
  builderNodes: [],
  builderEdges: [],
  selectedNodeId: null,
  executionState: null,

  // -----------------------------------------------------------------------
  // List
  // -----------------------------------------------------------------------

  fetchPlaybooks: async (params) => {
    set({ isLoading: true, error: null });
    try {
      const response = await listPlaybooks(params);
      set({ playbooks: response.items, isLoading: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to fetch playbooks";
      set({ isLoading: false, error: message });
    }
  },

  // -----------------------------------------------------------------------
  // CRUD
  // -----------------------------------------------------------------------

  createPlaybook: async (data) => {
    set({ isLoading: true, error: null });
    try {
      const playbook = await apiCreatePlaybook(data);
      set((state) => ({
        playbooks: [playbook, ...state.playbooks],
        currentPlaybook: playbook,
        isLoading: false,
      }));
      return playbook;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create playbook";
      set({ isLoading: false, error: message });
      throw err;
    }
  },

  savePlaybook: async (id) => {
    const { builderNodes, currentPlaybook } = get();
    if (!currentPlaybook) return;

    set({ isLoading: true, error: null });
    try {
      // Convert React Flow nodes/edges back to playbook steps
      const steps = builderNodes
        .filter((n) => n.type !== "trigger")
        .map((n): PlaybookStep => ({
          id: n.id,
          type:
            n.type === "hitlGate"
              ? StepType.HITL_GATE
              : n.type === "parallelFork"
                ? StepType.PARALLEL_FORK
                : ((n.type ?? "action") as StepType),
          name: String((n.data as Record<string, unknown>).label ?? n.id),
          description: "",
          config: {},
          next_step: null,
          on_failure: OnFailure.ABORT,
          ...(n.data as Record<string, unknown>),
        }));

      const triggerNode = builderNodes.find((n) => n.type === "trigger");
      const triggerData = triggerNode?.data as Record<string, unknown> | undefined;

      const updated = await apiUpdatePlaybook(id, {
        name: currentPlaybook.name,
        description: currentPlaybook.description,
        trigger: {
          type: (triggerData?.triggerType as TriggerType) ?? TriggerType.MANUAL,
          parameters: (triggerData?.parameters as Record<string, unknown>) ?? {},
        },
        steps,
      });

      set({
        currentPlaybook: updated,
        isLoading: false,
      });

      // Update in list
      set((state) => ({
        playbooks: state.playbooks.map((p) => (p.id === id ? updated : p)),
      }));
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to save playbook";
      set({ isLoading: false, error: message });
    }
  },

  setCurrentPlaybook: (playbook) => {
    set({ currentPlaybook: playbook });
  },

  loadPlaybook: async (id) => {
    set({ isLoading: true, error: null });
    try {
      const playbook = await getPlaybook(id);
      set({ currentPlaybook: playbook, isLoading: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load playbook";
      set({ isLoading: false, error: message });
    }
  },

  // -----------------------------------------------------------------------
  // Builder
  // -----------------------------------------------------------------------

  setBuilderNodes: (nodes) => set({ builderNodes: nodes }),
  setBuilderEdges: (edges) => set({ builderEdges: edges }),

  addNode: (node) =>
    set((state) => ({ builderNodes: [...state.builderNodes, node] })),

  updateNode: (id, data) =>
    set((state) => ({
      builderNodes: state.builderNodes.map((n) =>
        n.id === id ? { ...n, data: { ...n.data, ...data } } : n,
      ),
    })),

  removeNode: (id) =>
    set((state) => ({
      builderNodes: state.builderNodes.filter((n) => n.id !== id),
      builderEdges: state.builderEdges.filter(
        (e) => e.source !== id && e.target !== id,
      ),
      selectedNodeId: state.selectedNodeId === id ? null : state.selectedNodeId,
    })),

  connectNodes: (edge) =>
    set((state) => ({ builderEdges: [...state.builderEdges, edge] })),

  removeEdge: (id) =>
    set((state) => ({
      builderEdges: state.builderEdges.filter((e) => e.id !== id),
    })),

  setSelectedNode: (id) => set({ selectedNodeId: id }),

  clearBuilder: () =>
    set({
      builderNodes: [],
      builderEdges: [],
      selectedNodeId: null,
      currentPlaybook: null,
    }),

  // -----------------------------------------------------------------------
  // Execution
  // -----------------------------------------------------------------------

  executePlaybook: async (id, investigationId) => {
    set({ isLoading: true, error: null });
    try {
      const execution = await apiExecutePlaybook(id, investigationId);
      set({ executionState: execution, isLoading: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to execute playbook";
      set({ isLoading: false, error: message });
    }
  },

  fetchExecution: async (executionId) => {
    try {
      const execution = await getExecution(executionId);
      set({ executionState: execution });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to fetch execution";
      set({ error: message });
    }
  },

  setExecutionState: (execution) => set({ executionState: execution }),

  clearError: () => set({ error: null }),
}));
