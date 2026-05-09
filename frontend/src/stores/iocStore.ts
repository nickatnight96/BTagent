import { create } from "zustand";
import type { IOC, IOCFilter, IOCSortConfig, ImportResult, ExportOptions } from "@/types/ioc";
import {
  listIOCs,
  getIOC as fetchIOCById,
  enrichIOC as enrichIOCApi,
  bulkEnrich as bulkEnrichApi,
  importCSV,
  importSTIX,
  exportIOCs as exportIOCsApi,
} from "@/api/iocs";

interface IOCState {
  iocs: IOC[];
  selectedIOCId: string | null;
  selectedIOC: IOC | null;
  filters: IOCFilter;
  sort: IOCSortConfig;
  isLoading: boolean;
  isEnriching: boolean;
  isImporting: boolean;
  isExporting: boolean;
  error: string | null;
  total: number;
  page: number;
  pageSize: number;
  selectedIds: Set<string>;

  fetchIOCs: (params?: { page?: number }) => Promise<void>;
  fetchIOC: (id: string) => Promise<void>;
  enrichIOC: (id: string) => Promise<void>;
  bulkEnrich: (ids: string[]) => Promise<void>;
  importIOCs: (data: string, format: "csv" | "stix", investigationId?: string) => Promise<ImportResult>;
  exportIOCs: (options: ExportOptions) => Promise<void>;
  setFilters: (filters: Partial<IOCFilter>) => void;
  setSort: (sort: IOCSortConfig) => void;
  selectIOC: (id: string | null) => void;
  toggleSelected: (id: string) => void;
  selectAll: () => void;
  clearSelection: () => void;
  clearError: () => void;
}

export const useIOCStore = create<IOCState>((set, get) => ({
  iocs: [],
  selectedIOCId: null,
  selectedIOC: null,
  filters: {},
  sort: { field: "first_seen", direction: "desc" },
  isLoading: false,
  isEnriching: false,
  isImporting: false,
  isExporting: false,
  error: null,
  total: 0,
  page: 1,
  pageSize: 50,
  selectedIds: new Set(),

  fetchIOCs: async (params) => {
    set({ isLoading: true, error: null });
    try {
      const { filters, sort, pageSize } = get();
      const page = params?.page ?? get().page;
      const response = await listIOCs({
        ...filters,
        page,
        page_size: pageSize,
        sort_by: sort.field,
        sort_dir: sort.direction,
      });
      set({
        iocs: response.items,
        total: response.total,
        page: response.page,
        isLoading: false,
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch IOCs";
      set({ isLoading: false, error: message });
    }
  },

  fetchIOC: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      const ioc = await fetchIOCById(id);
      set((state) => {
        const index = state.iocs.findIndex((i) => i.id === id);
        const updated = [...state.iocs];
        if (index >= 0) {
          updated[index] = ioc;
        }
        return {
          selectedIOC: ioc,
          selectedIOCId: id,
          iocs: updated,
          isLoading: false,
        };
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch IOC";
      set({ isLoading: false, error: message });
    }
  },

  enrichIOC: async (id: string) => {
    set({ isEnriching: true, error: null });
    try {
      const enriched = await enrichIOCApi(id);
      set((state) => {
        const updated = state.iocs.map((ioc) =>
          ioc.id === id ? enriched : ioc,
        );
        return {
          iocs: updated,
          selectedIOC:
            state.selectedIOCId === id ? enriched : state.selectedIOC,
          isEnriching: false,
        };
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to enrich IOC";
      set({ isEnriching: false, error: message });
    }
  },

  bulkEnrich: async (ids: string[]) => {
    set({ isEnriching: true, error: null });
    try {
      const { results } = await bulkEnrichApi(ids);
      const enrichedMap = new Map(results.map((ioc) => [ioc.id, ioc]));
      set((state) => ({
        iocs: state.iocs.map((ioc) => enrichedMap.get(ioc.id) ?? ioc),
        isEnriching: false,
        selectedIds: new Set(),
      }));
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to bulk enrich IOCs";
      set({ isEnriching: false, error: message });
    }
  },

  importIOCs: async (data, format, investigationId) => {
    set({ isImporting: true, error: null });
    try {
      const importer = format === "csv" ? importCSV : importSTIX;
      const result = await importer(data, investigationId);
      // Refresh the list after import
      await get().fetchIOCs();
      set({ isImporting: false });
      return result;
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to import IOCs";
      set({ isImporting: false, error: message });
      throw err;
    }
  },

  exportIOCs: async (options) => {
    set({ isExporting: true, error: null });
    try {
      const blob = await exportIOCsApi(options);
      // Trigger browser download
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const ext =
        options.format === "stix_2.1"
          ? "json"
          : options.format === "csv"
            ? "csv"
            : "json";
      a.href = url;
      a.download = `iocs_export_${Date.now()}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      set({ isExporting: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to export IOCs";
      set({ isExporting: false, error: message });
    }
  },

  setFilters: (filters) => {
    set((state) => ({
      filters: { ...state.filters, ...filters },
      page: 1,
    }));
  },

  setSort: (sort) => {
    set({ sort });
  },

  selectIOC: (id) => {
    if (id === null) {
      set({ selectedIOCId: null, selectedIOC: null });
    } else {
      const ioc = get().iocs.find((i) => i.id === id) ?? null;
      set({ selectedIOCId: id, selectedIOC: ioc });
      if (id) {
        void get().fetchIOC(id);
      }
    }
  },

  toggleSelected: (id) => {
    set((state) => {
      const next = new Set(state.selectedIds);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return { selectedIds: next };
    });
  },

  selectAll: () => {
    set((state) => ({
      selectedIds: new Set(state.iocs.map((i) => i.id)),
    }));
  },

  clearSelection: () => {
    set({ selectedIds: new Set() });
  },

  clearError: () => set({ error: null }),
}));
