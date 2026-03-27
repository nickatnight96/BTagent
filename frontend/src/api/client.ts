const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

interface RequestOptions extends RequestInit {
  skipAuth?: boolean;
}

class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public body: unknown,
  ) {
    super(`API Error ${status}: ${statusText}`);
    this.name = "ApiError";
  }
}

interface AuthStoreSlice {
  accessToken: string | null;
  refreshTokens: () => Promise<boolean>;
  logout: () => void;
}

// Auth store accessor, set externally to avoid circular dependency
let _getAuthState: (() => AuthStoreSlice) | null = null;

export function setAuthStoreAccessor(accessor: () => AuthStoreSlice): void {
  _getAuthState = accessor;
}

function getAuthStore(): AuthStoreSlice {
  if (!_getAuthState) {
    throw new Error("Auth store accessor not configured. Call setAuthStoreAccessor() first.");
  }
  return _getAuthState();
}

async function request<T>(
  endpoint: string,
  options: RequestOptions = {},
): Promise<T> {
  const { skipAuth = false, headers: customHeaders, ...rest } = options;

  const headers = new Headers(customHeaders);

  if (!headers.has("Content-Type") && !(rest.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  if (!skipAuth) {
    const authState = getAuthStore();
    if (authState.accessToken) {
      headers.set("Authorization", `Bearer ${authState.accessToken}`);
    }
  }

  const url = endpoint.startsWith("http") ? endpoint : `${BASE_URL}${endpoint}`;

  let response = await fetch(url, { ...rest, headers });

  // Auto-refresh on 401
  if (response.status === 401 && !skipAuth) {
    const authState = getAuthStore();
    const refreshed = await authState.refreshTokens();
    if (refreshed) {
      const retryAuthState = getAuthStore();
      if (retryAuthState.accessToken) {
        headers.set("Authorization", `Bearer ${retryAuthState.accessToken}`);
      }
      response = await fetch(url, { ...rest, headers });
    } else {
      authState.logout();
      throw new ApiError(401, "Unauthorized", null);
    }
  }

  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = await response.text();
    }
    throw new ApiError(response.status, response.statusText, body);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export const api = {
  get<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return request<T>(endpoint, { ...options, method: "GET" });
  },

  post<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(endpoint, {
      ...options,
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    });
  },

  put<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(endpoint, {
      ...options,
      method: "PUT",
      body: body ? JSON.stringify(body) : undefined,
    });
  },

  patch<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(endpoint, {
      ...options,
      method: "PATCH",
      body: body ? JSON.stringify(body) : undefined,
    });
  },

  delete<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return request<T>(endpoint, { ...options, method: "DELETE" });
  },
};

export { ApiError };
export default api;
