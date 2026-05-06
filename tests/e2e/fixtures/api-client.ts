/**
 * Thin HTTP wrapper around the BTagent backend for E2E test setup.
 *
 * Tests use this to seed state (users, investigations, IOCs, knowledge
 * docs) without having to drive the full UI for every precondition. The
 * client speaks both transports the backend accepts:
 *
 *   * httpOnly cookie  — same as the SPA
 *   * Authorization header — for tests that want to assert the
 *     compat-fallback path still works
 *
 * Login uses the cookie path by default (matches the SPA's behaviour
 * in the post-Phase-C1 build). Tests that need the header path call
 * ``loginWithHeaderToken`` instead and the returned client carries the
 * ``Authorization: Bearer …`` header on every subsequent request.
 */
import { request, type APIRequestContext } from "@playwright/test";

const API_URL = process.env.E2E_API_URL ?? "http://localhost:8000";

export interface SeededInvestigation {
  id: string;
  title: string;
  description?: string;
  severity: "low" | "medium" | "high" | "critical";
  tlp_level: "white" | "green" | "amber" | "red";
  status: string;
  assigned_to?: string;
}

export interface SeededIOC {
  id: string;
  investigation_id: string;
  type: "ip" | "domain" | "url" | "hash" | "email" | "cve";
  value: string;
  confidence?: number;
  tlp_level: "white" | "green" | "amber" | "red";
}

export interface AuthCredentials {
  username: string;
  password: string;
}

/** Persona credentials seeded by ``infra/scripts/seed-data.py`` in test mode. */
export const TEST_CREDENTIALS: Record<
  "admin" | "analyst" | "senior",
  AuthCredentials
> = {
  // In ``BTAGENT_ENV=test``, the seeder uses ``password === username``
  // so deterministic logins work in CI without leaking real secrets.
  admin: { username: "admin", password: "admin" },
  analyst: { username: "analyst1", password: "analyst1" },
  senior: { username: "senior1", password: "senior1" },
};

export class BTAgentApiClient {
  private constructor(
    public readonly ctx: APIRequestContext,
    public readonly accessToken: string | null,
  ) {}

  /** Build a fresh client — no auth yet. Use ``login()`` next. */
  static async newAnonymous(): Promise<BTAgentApiClient> {
    const ctx = await request.newContext({
      baseURL: API_URL,
      extraHTTPHeaders: { "x-e2e-test": "1" },
    });
    return new BTAgentApiClient(ctx, null);
  }

  /**
   * Authenticate via the cookie transport (the path the SPA uses).
   *
   * Returns a *new* client whose request context inherits the ``Set-Cookie``
   * jar from the login response, so subsequent calls are authenticated.
   */
  static async loginWithCookie(
    creds: AuthCredentials,
  ): Promise<BTAgentApiClient> {
    const ctx = await request.newContext({
      baseURL: API_URL,
      extraHTTPHeaders: { "x-e2e-test": "1" },
    });
    const res = await ctx.post("/api/v1/auth/login", {
      data: { username: creds.username, password: creds.password },
    });
    if (!res.ok()) {
      throw new Error(
        `Login failed for ${creds.username}: ${res.status()} ${await res.text()}`,
      );
    }
    return new BTAgentApiClient(ctx, null);
  }

  /**
   * Authenticate via the Authorization header transport.
   *
   * Returns the access token as a string in addition to a new client
   * configured to send it on every request. Used by the WS-via-cookie
   * regression test and by callers that want to assert the
   * dual-transport compat path still works.
   */
  static async loginWithHeaderToken(
    creds: AuthCredentials,
  ): Promise<BTAgentApiClient> {
    const tmp = await request.newContext({
      baseURL: API_URL,
      extraHTTPHeaders: { "x-e2e-test": "1" },
    });
    const res = await tmp.post("/api/v1/auth/login", {
      data: { username: creds.username, password: creds.password },
    });
    if (!res.ok()) {
      throw new Error(
        `Login failed for ${creds.username}: ${res.status()} ${await res.text()}`,
      );
    }
    const body = (await res.json()) as { access_token: string };
    await tmp.dispose();

    const ctx = await request.newContext({
      baseURL: API_URL,
      extraHTTPHeaders: {
        "x-e2e-test": "1",
        Authorization: `Bearer ${body.access_token}`,
      },
    });
    return new BTAgentApiClient(ctx, body.access_token);
  }

  /** Log out — invalidates the access-token jti server-side. */
  async logout(): Promise<void> {
    await this.ctx.post("/api/v1/auth/logout");
  }

  /** Dispose the underlying context. Call in test ``afterEach``. */
  async dispose(): Promise<void> {
    await this.ctx.dispose();
  }

  // ------------------------------------------------------------------
  // Investigations
  // ------------------------------------------------------------------

  async createInvestigation(payload: {
    title: string;
    description?: string;
    severity?: "low" | "medium" | "high" | "critical";
    tlp_level?: "white" | "green" | "amber" | "red";
    assigned_to?: string;
    tags?: string[];
  }): Promise<SeededInvestigation> {
    const res = await this.ctx.post("/api/v1/investigations", {
      data: {
        severity: "medium",
        tlp_level: "green",
        ...payload,
      },
    });
    if (!res.ok()) {
      throw new Error(
        `Create investigation failed: ${res.status()} ${await res.text()}`,
      );
    }
    return (await res.json()) as SeededInvestigation;
  }

  async getInvestigation(id: string): Promise<SeededInvestigation> {
    const res = await this.ctx.get(`/api/v1/investigations/${id}`);
    if (!res.ok()) {
      throw new Error(
        `Get investigation ${id} failed: ${res.status()} ${await res.text()}`,
      );
    }
    return (await res.json()) as SeededInvestigation;
  }

  async listInvestigations(): Promise<SeededInvestigation[]> {
    const res = await this.ctx.get("/api/v1/investigations");
    if (!res.ok()) {
      throw new Error(
        `List investigations failed: ${res.status()} ${await res.text()}`,
      );
    }
    return (await res.json()) as SeededInvestigation[];
  }

  // ------------------------------------------------------------------
  // IOCs
  // ------------------------------------------------------------------

  async addIOC(payload: {
    investigation_id: string;
    type: SeededIOC["type"];
    value: string;
    confidence?: number;
    tlp_level?: "white" | "green" | "amber" | "red";
    source?: string;
  }): Promise<SeededIOC> {
    const res = await this.ctx.post("/api/v1/iocs", {
      data: {
        confidence: 0.7,
        tlp_level: "green",
        source: "e2e-test",
        ...payload,
      },
    });
    if (!res.ok()) {
      throw new Error(`Add IOC failed: ${res.status()} ${await res.text()}`);
    }
    return (await res.json()) as SeededIOC;
  }

  async listIOCs(investigationId: string): Promise<SeededIOC[]> {
    const res = await this.ctx.get(
      `/api/v1/investigations/${investigationId}/iocs`,
    );
    if (!res.ok()) {
      throw new Error(
        `List IOCs failed: ${res.status()} ${await res.text()}`,
      );
    }
    return (await res.json()) as SeededIOC[];
  }

  // ------------------------------------------------------------------
  // Knowledge
  // ------------------------------------------------------------------

  async ingestKnowledgeDoc(payload: {
    title: string;
    content: string;
    source_type?: string;
    classification?: "white" | "green" | "amber" | "red";
  }): Promise<{ id: string; title: string }> {
    const res = await this.ctx.post("/api/v1/knowledge/ingest", {
      data: {
        source_type: "runbook",
        classification: "green",
        ...payload,
      },
    });
    if (!res.ok()) {
      throw new Error(
        `Ingest knowledge doc failed: ${res.status()} ${await res.text()}`,
      );
    }
    return (await res.json()) as { id: string; title: string };
  }

  // ------------------------------------------------------------------
  // Health / utility
  // ------------------------------------------------------------------

  async health(): Promise<boolean> {
    try {
      const res = await this.ctx.get("/api/v1/health");
      return res.ok();
    } catch {
      return false;
    }
  }
}
