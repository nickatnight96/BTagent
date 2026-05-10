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
  // Phase C2: tokens live in httpOnly cookies. The store no longer holds
  // them. We only need a hook for the 401 path so the client can clear the
  // local user and bounce to /login.
  logout: () => Promise<void> | void;
  // Local-only sibling of ``logout``: clears the in-memory user
  // without round-tripping ``/auth/logout``. Used when the SERVER has
  // already invalidated the session (e.g. we got a 401), so calling
  // the network logout would just add the cookie's jti to the
  // revocation list — which cascades into other tabs / parallel test
  // workers sharing the same access token.
  clearLocalUser: () => void;
}

// Auth store accessor, set externally to avoid circular dependency.
let _getAuthState: (() => AuthStoreSlice) | null = null;

// Optional unauthenticated handler — installed by App bootstrap so the
// client can redirect on 401 without importing react-router here.
let _onUnauthenticated: (() => void) | null = null;

export function setAuthStoreAccessor(accessor: () => AuthStoreSlice): void {
  _getAuthState = accessor;
}

export function setUnauthenticatedHandler(handler: () => void): void {
  _onUnauthenticated = handler;
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

  const url = endpoint.startsWith("http") ? endpoint : `${BASE_URL}${endpoint}`;

  // `credentials: "include"` makes the browser attach the httpOnly auth
  // cookies to every API call. The server reads them; JS never sees them.
  const response = await fetch(url, {
    ...rest,
    headers,
    credentials: "include",
  });

  if (response.status === 401 && !skipAuth) {
    // Cookie missing/expired/revoked. Clear the LOCAL user state and
    // let the installed handler (typically a router redirect) take
    // over. We deliberately do NOT call the network ``logout()`` here:
    // a 401 already means the cookie is dead on the server, and
    // POSTing /auth/logout would put the jti on the revocation list —
    // which, in parallel test runs (or any multi-tab session that
    // shares cookies), propagates the revocation to every other
    // context using the same access token.
    try {
      getAuthStore().clearLocalUser();
    } catch {
      // ignore — we're already in the failure path
    }
    if (_onUnauthenticated) {
      _onUnauthenticated();
    }
    throw new ApiError(401, "Unauthorized", null);
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
