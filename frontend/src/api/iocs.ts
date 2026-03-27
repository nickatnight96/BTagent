import api from "./client";
import type {
  IOC,
  IOCFilter,
  ImportResult,
  ExportOptions,
} from "@/types/ioc";

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

interface ListIOCsParams extends IOCFilter {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_dir?: "asc" | "desc";
}

function buildQuery(params: Record<string, unknown>): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      searchParams.set(key, String(value));
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : "";
}

export async function listIOCs(
  params: ListIOCsParams = {},
): Promise<PaginatedResponse<IOC>> {
  const endpoint = `/v1/iocs${buildQuery(params)}`;
  return api.get<PaginatedResponse<IOC>>(endpoint);
}

export async function getIOC(id: string): Promise<IOC> {
  return api.get<IOC>(`/v1/iocs/${id}`);
}

export async function createIOC(
  data: Partial<IOC> & { type: string; value: string },
): Promise<IOC> {
  return api.post<IOC>("/v1/iocs", data);
}

export async function updateIOC(
  id: string,
  data: Partial<IOC>,
): Promise<IOC> {
  return api.patch<IOC>(`/v1/iocs/${id}`, data);
}

export async function deleteIOC(id: string): Promise<void> {
  return api.delete<void>(`/v1/iocs/${id}`);
}

export async function enrichIOC(id: string): Promise<IOC> {
  return api.post<IOC>(`/v1/iocs/${id}/enrich`);
}

export async function bulkEnrich(ids: string[]): Promise<{ results: IOC[] }> {
  return api.post<{ results: IOC[] }>("/v1/iocs/bulk-enrich", { ids });
}

export async function searchIOCs(
  query: string,
  filters?: IOCFilter,
): Promise<PaginatedResponse<IOC>> {
  const params = { search: query, ...filters };
  const endpoint = `/v1/iocs${buildQuery(params)}`;
  return api.get<PaginatedResponse<IOC>>(endpoint);
}

export async function importSTIX(
  data: string,
  investigationId?: string,
): Promise<ImportResult> {
  return api.post<ImportResult>("/v1/iocs/import/stix", {
    data,
    investigation_id: investigationId,
  });
}

export async function importCSV(
  data: string,
  investigationId?: string,
): Promise<ImportResult> {
  return api.post<ImportResult>("/v1/iocs/import/csv", {
    data,
    investigation_id: investigationId,
  });
}

export async function exportIOCs(
  options: ExportOptions,
): Promise<Blob> {
  const endpoint = `/v1/iocs/export${buildQuery(options as unknown as Record<string, unknown>)}`;
  const response = await fetch(
    `${import.meta.env.VITE_API_BASE_URL ?? "/api"}${endpoint}`,
    {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    },
  );
  return response.blob();
}
