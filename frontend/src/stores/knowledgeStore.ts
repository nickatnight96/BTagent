import { create } from "zustand";
import type {
  KnowledgeDocument,
  KnowledgeSearchResult,
  KnowledgeSourceType,
} from "@/types/knowledge";
import {
  deleteDocument as deleteDocApi,
  ingestDocument,
  listDocuments,
  queryKnowledge,
  searchKnowledge,
} from "@/api/knowledge";

interface KnowledgeState {
  /** Document list */
  documents: KnowledgeDocument[];
  totalDocuments: number;
  documentsPage: number;
  documentsPageSize: number;

  /** Search state */
  searchQuery: string;
  searchResults: KnowledgeSearchResult[];
  totalResults: number;
  sourceFilter: KnowledgeSourceType | null;

  /** Loading flags */
  isLoading: boolean;
  isSearching: boolean;
  isIngesting: boolean;

  /** Error */
  error: string | null;

  /** Actions */
  fetchDocuments: (params?: { page?: number; source_type?: string }) => Promise<void>;
  search: (query: string, sourceType?: string) => Promise<void>;
  hybridSearch: (query: string, topK?: number, sourceType?: string) => Promise<void>;
  ingest: (title: string, content: string, sourceType: string, metadata?: Record<string, unknown>) => Promise<string>;
  deleteDocument: (id: string) => Promise<void>;
  setSourceFilter: (filter: KnowledgeSourceType | null) => void;
  setSearchQuery: (query: string) => void;
  clearError: () => void;
  clearSearch: () => void;
}

export const useKnowledgeStore = create<KnowledgeState>((set, get) => ({
  documents: [],
  totalDocuments: 0,
  documentsPage: 1,
  documentsPageSize: 20,

  searchQuery: "",
  searchResults: [],
  totalResults: 0,
  sourceFilter: null,

  isLoading: false,
  isSearching: false,
  isIngesting: false,

  error: null,

  fetchDocuments: async (params) => {
    set({ isLoading: true, error: null });
    try {
      const { sourceFilter, documentsPageSize } = get();
      const response = await listDocuments({
        page: params?.page ?? get().documentsPage,
        page_size: documentsPageSize,
        source_type: params?.source_type ?? sourceFilter ?? undefined,
      });
      // Defensive fallback to ``[]`` so a malformed response (or
      // mocked stub) can't crash the page with "Cannot read
      // properties of undefined (reading 'length')".
      set({
        documents: response.items ?? [],
        totalDocuments: response.total ?? 0,
        documentsPage: response.page ?? 1,
        isLoading: false,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to fetch documents";
      set({ isLoading: false, error: message });
    }
  },

  search: async (query, sourceType) => {
    if (!query.trim()) {
      set({ searchResults: [], totalResults: 0 });
      return;
    }
    set({ isSearching: true, error: null, searchQuery: query });
    try {
      const response = await searchKnowledge(query, 10, sourceType);
      set({
        searchResults: response.results,
        totalResults: response.total_results,
        isSearching: false,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Search failed";
      set({ isSearching: false, error: message });
    }
  },

  hybridSearch: async (query, topK, sourceType) => {
    if (!query.trim()) {
      set({ searchResults: [], totalResults: 0 });
      return;
    }
    set({ isSearching: true, error: null, searchQuery: query });
    try {
      const response = await queryKnowledge(query, topK ?? 5, sourceType);
      set({
        searchResults: response.results,
        totalResults: response.total_results,
        isSearching: false,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Hybrid search failed";
      set({ isSearching: false, error: message });
    }
  },

  ingest: async (title, content, sourceType, metadata) => {
    set({ isIngesting: true, error: null });
    try {
      const response = await ingestDocument({ title, content, source_type: sourceType, metadata });
      // Refresh document list
      await get().fetchDocuments();
      set({ isIngesting: false });
      return response.id;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to ingest document";
      set({ isIngesting: false, error: message });
      throw err;
    }
  },

  deleteDocument: async (id) => {
    set({ isLoading: true, error: null });
    try {
      await deleteDocApi(id);
      await get().fetchDocuments();
      set({ isLoading: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to delete document";
      set({ isLoading: false, error: message });
    }
  },

  setSourceFilter: (filter) => {
    set({ sourceFilter: filter, documentsPage: 1 });
  },

  setSearchQuery: (query) => {
    set({ searchQuery: query });
  },

  clearError: () => set({ error: null }),

  clearSearch: () => set({ searchQuery: "", searchResults: [], totalResults: 0 }),
}));
