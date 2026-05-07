/**
 * High-level seed helpers — domain-shaped test data setup.
 *
 * Tests should never call the API directly to set up state; they use
 * these helpers so the shape of "an investigation with three IOCs and
 * a runbook attached" is named once and reused.
 *
 * Why an extra layer over ``BTAgentApiClient``: when the API surface
 * changes (Phase 2 adds workflow CRUD, Phase 3 adds triggers), we
 * change one helper here instead of every test that needed a seeded
 * scenario.
 */
import { BTAgentApiClient, type SeededInvestigation, type SeededIOC } from "./api-client";

export interface SeedScenarioResult {
  investigation: SeededInvestigation;
  iocs: SeededIOC[];
}

/**
 * Standard "fresh investigation with a few IOCs" scenario — the most
 * common test starting point.
 *
 * Defaults: title prefixed with ``[E2E]`` so seed/test data is easy
 * to spot in logs and (when needed) clean up. Three IOCs covering the
 * three most-common types (ip / domain / hash).
 */
export async function seedInvestigationWithIOCs(
  api: BTAgentApiClient,
  overrides: {
    title?: string;
    description?: string;
    severity?: "low" | "medium" | "high" | "critical";
    tlp_level?: "white" | "green" | "amber" | "red";
    iocs?: Array<{
      type: SeededIOC["type"];
      value: string;
      tlp_level?: "white" | "green" | "amber" | "red";
    }>;
  } = {},
): Promise<SeedScenarioResult> {
  const investigation = await api.createInvestigation({
    title: overrides.title ?? `[E2E] Investigation ${Date.now()}`,
    description:
      overrides.description ??
      "Seeded investigation for end-to-end test coverage.",
    severity: overrides.severity ?? "medium",
    tlp_level: overrides.tlp_level ?? "green",
  });

  const iocSpecs = overrides.iocs ?? [
    { type: "ip" as const, value: "203.0.113.42" },
    { type: "domain" as const, value: "phish.example.invalid" },
    {
      type: "hash" as const,
      value: "44d88612fea8a8f36de82e1278abb02f",
    },
  ];
  const iocs: SeededIOC[] = [];
  for (const spec of iocSpecs) {
    const ioc = await api.addIOC({
      investigation_id: investigation.id,
      type: spec.type,
      value: spec.value,
      tlp_level: spec.tlp_level ?? "green",
    });
    iocs.push(ioc);
  }
  return { investigation, iocs };
}

/**
 * Seed an investigation tagged TLP:RED with one TLP:RED IOC. Use to
 * exercise the egress-block paths (STIX export, Knowledge ingest,
 * MCP return, WebSocket emit).
 */
export async function seedRedInvestigation(
  api: BTAgentApiClient,
): Promise<SeedScenarioResult> {
  return seedInvestigationWithIOCs(api, {
    title: `[E2E] [RED] Restricted Case ${Date.now()}`,
    tlp_level: "red",
    severity: "high",
    iocs: [{ type: "ip", value: "198.51.100.7", tlp_level: "red" }],
  });
}

/**
 * Seed a knowledge document — green-classified runbook. Used to
 * exercise RAG search + auto-injection paths.
 */
export async function seedKnowledgeDoc(
  api: BTAgentApiClient,
  overrides: { title?: string; content?: string } = {},
): Promise<{ id: string; title: string }> {
  return api.ingestKnowledgeDoc({
    title: overrides.title ?? `[E2E] Runbook ${Date.now()}`,
    content:
      overrides.content ??
      "Lateral-movement detection: pivot to host telemetry on every Kerberos golden-ticket alert.",
    source_type: "runbook",
    classification: "green",
  });
}
