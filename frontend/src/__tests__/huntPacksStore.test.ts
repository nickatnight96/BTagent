/**
 * Unit tests for the huntPacksStore pure derivation helpers + Zustand store
 * (#112 Phase B). Store surface (fetchAll, togglePackEnabled, selectRule) is
 * exercised with mocked API calls — mirrors patternStore/cloudStore tests.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import type {
  HuntPackCatalogEntry,
  HuntPackRun,
  HuntPackRunRuleStat,
  NoiseBaseline,
} from "@/types/hunt";
import {
  buildInstalledPacks,
  build30dHitVolume,
  classifyRuleState,
  groupRunsByPack,
  indexBaseline,
  indexCatalog,
  HIT_VOLUME_DAYS,
} from "@/stores/huntPacksStore";

// --------------------------------------------------------------------------- //
// Fixtures
// --------------------------------------------------------------------------- //

function ruleStat(overrides: Partial<HuntPackRunRuleStat> = {}): HuntPackRunRuleStat {
  return { title: "Rule", hits: 0, errors: 0, ...overrides };
}

function run(overrides: Partial<HuntPackRun> & { id: string }): HuntPackRun {
  return {
    org_id: "org_default",
    run_id: `hrun_${overrides.id}`,
    pack_id: "hpack_win",
    pack_name: "Windows Baseline",
    pack_version: "1.0.0",
    backends: ["splunk"],
    rule_stats: {},
    hit_count: 0,
    error_count: 0,
    findings_created: 0,
    status: "completed",
    error: null,
    started_at: "2026-07-27T10:00:00Z",
    completed_at: "2026-07-27T10:00:05Z",
    ...overrides,
  };
}

function baseline(items: NoiseBaseline["items"]): NoiseBaseline {
  return { items, runs_analyzed: items.length, min_runs: 3, hit_rate_threshold: 0.8 };
}

function catalogEntry(
  overrides: Partial<HuntPackCatalogEntry> & { pack_id: string; manifest_pack_id: string },
): HuntPackCatalogEntry {
  return {
    name: "Windows Baseline",
    version: "1.0.0",
    description: "",
    rule_count: 4,
    source: "builtin",
    enabled: true,
    installed: false,
    default_enabled: true,
    installed_at: null,
    updated_at: null,
    updated_by: null,
    ...overrides,
  };
}

function noisyRule(pack_id: string, rule_id: string) {
  return {
    pack_id,
    pack_name: "Windows Baseline",
    rule_id,
    rule_title: rule_id,
    runs_observed: 10,
    runs_hit: 10,
    hit_rate: 1,
    total_hits: 40,
    avg_hits_per_run: 4,
    last_hit_at: "2026-07-27T10:00:00Z",
  };
}

// --------------------------------------------------------------------------- //
// groupRunsByPack
// --------------------------------------------------------------------------- //

describe("groupRunsByPack", () => {
  it("groups by pack_id and sorts each group newest-first", () => {
    const groups = groupRunsByPack([
      run({ id: "a", pack_id: "p1", started_at: "2026-07-20T10:00:00Z" }),
      run({ id: "b", pack_id: "p1", started_at: "2026-07-25T10:00:00Z" }),
      run({ id: "c", pack_id: "p2", started_at: "2026-07-21T10:00:00Z" }),
    ]);
    expect([...groups.keys()].sort()).toEqual(["p1", "p2"]);
    expect(groups.get("p1")!.map((r) => r.id)).toEqual(["b", "a"]);
    expect(groups.get("p2")!).toHaveLength(1);
  });
});

// --------------------------------------------------------------------------- //
// build30dHitVolume
// --------------------------------------------------------------------------- //

describe("build30dHitVolume", () => {
  const now = new Date("2026-07-27T12:00:00Z");

  it("returns exactly HIT_VOLUME_DAYS points, oldest first, ending today", () => {
    const pts = build30dHitVolume([], now);
    expect(pts).toHaveLength(HIT_VOLUME_DAYS);
    expect(pts[pts.length - 1]!.day).toBe("2026-07-27");
    expect(pts.every((p) => p.hits === 0)).toBe(true);
  });

  it("sums hit_count into the run's UTC day and zero-fills empty days", () => {
    const pts = build30dHitVolume(
      [
        run({ id: "a", started_at: "2026-07-27T01:00:00Z", hit_count: 3 }),
        run({ id: "b", started_at: "2026-07-27T20:00:00Z", hit_count: 4 }),
        run({ id: "c", started_at: "2026-07-20T09:00:00Z", hit_count: 2 }),
      ],
      now,
    );
    const today = pts.find((p) => p.day === "2026-07-27");
    const jul20 = pts.find((p) => p.day === "2026-07-20");
    const jul21 = pts.find((p) => p.day === "2026-07-21");
    expect(today!.hits).toBe(7); // 3 + 4 same day
    expect(jul20!.hits).toBe(2);
    expect(jul21!.hits).toBe(0);
  });

  it("drops runs older than the window", () => {
    const pts = build30dHitVolume(
      [run({ id: "old", started_at: "2026-01-01T00:00:00Z", hit_count: 99 })],
      now,
    );
    expect(pts.reduce((s, p) => s + p.hits, 0)).toBe(0);
  });
});

// --------------------------------------------------------------------------- //
// classifyRuleState
// --------------------------------------------------------------------------- //

describe("classifyRuleState", () => {
  const empty = indexBaseline(null);

  it("errored when the latest run's rule had an error", () => {
    const runs = [
      run({ id: "r", rule_stats: { rule1: ruleStat({ hits: 0, errors: 1 }) } }),
    ];
    expect(classifyRuleState("rule1", "hpack_win", runs, empty)).toBe("errored");
  });

  it("over_firing when the rule is on the noise baseline (even if it also hits)", () => {
    const idx = indexBaseline(baseline([noisyRule("hpack_win", "rule1")]));
    const runs = [run({ id: "r", rule_stats: { rule1: ruleStat({ hits: 5 }) } })];
    expect(classifyRuleState("rule1", "hpack_win", runs, idx)).toBe("over_firing");
  });

  it("under_firing when observed in >=3 runs and never hit", () => {
    const runs = [
      run({ id: "1", rule_stats: { rule1: ruleStat({ hits: 0 }) } }),
      run({ id: "2", rule_stats: { rule1: ruleStat({ hits: 0 }) } }),
      run({ id: "3", rule_stats: { rule1: ruleStat({ hits: 0 }) } }),
    ];
    expect(classifyRuleState("rule1", "hpack_win", runs, empty)).toBe("under_firing");
  });

  it("firing_as_expected when the latest run hit and it is not chronic", () => {
    const runs = [
      run({ id: "1", rule_stats: { rule1: ruleStat({ hits: 2 }) } }),
      run({ id: "2", rule_stats: { rule1: ruleStat({ hits: 0 }) } }),
    ];
    expect(classifyRuleState("rule1", "hpack_win", runs, empty)).toBe("firing_as_expected");
  });

  it("clean when the latest run was quiet and not enough zero-runs for under-firing", () => {
    const runs = [run({ id: "1", rule_stats: { rule1: ruleStat({ hits: 0 }) } })];
    expect(classifyRuleState("rule1", "hpack_win", runs, empty)).toBe("clean");
  });
});

// --------------------------------------------------------------------------- //
// buildInstalledPacks
// --------------------------------------------------------------------------- //

describe("buildInstalledPacks", () => {
  it("rolls run history into installed packs with per-rule state + queries", () => {
    const runs = [
      run({
        id: "new",
        pack_id: "hpack_win",
        started_at: "2026-07-27T10:00:00Z",
        hit_count: 5,
        rule_stats: {
          ruleA: ruleStat({ title: "Alpha", hits: 5, queries: { splunk: "search A" } }),
          ruleB: ruleStat({ title: "Bravo", hits: 0, errors: 2 }),
        },
      }),
      run({
        id: "old",
        pack_id: "hpack_win",
        started_at: "2026-07-26T10:00:00Z",
        hit_count: 1,
        rule_stats: { ruleA: ruleStat({ title: "Alpha", hits: 1 }) },
      }),
    ];
    const packs = buildInstalledPacks(runs, baseline([noisyRule("hpack_win", "ruleA")]));
    expect(packs).toHaveLength(1);
    const pack = packs[0]!;
    expect(pack.pack_id).toBe("hpack_win");
    expect(pack.run_count).toBe(2);
    expect(pack.last_run!.id).toBe("new"); // newest run
    expect(pack.hit_volume_30d).toHaveLength(HIT_VOLUME_DAYS);

    const byId = Object.fromEntries(pack.rules.map((r) => [r.rule_id, r]));
    // ruleA is on the baseline -> over_firing; carries its latest query.
    expect(byId.ruleA!.state).toBe("over_firing");
    expect(byId.ruleA!.queries).toEqual({ splunk: "search A" });
    expect(byId.ruleA!.total_hits).toBe(6); // 5 + 1 across runs
    // ruleB errored on its latest (only) run.
    expect(byId.ruleB!.state).toBe("errored");
    expect(byId.ruleB!.last_errors).toBe(2);
  });

  it("sorts packs by name", () => {
    const packs = buildInstalledPacks(
      [
        run({ id: "z", pack_id: "p_z", pack_name: "Zeta", rule_stats: {} }),
        run({ id: "a", pack_id: "p_a", pack_name: "Alpha", rule_stats: {} }),
      ],
      null,
    );
    expect(packs.map((p) => p.pack_name)).toEqual(["Alpha", "Zeta"]);
  });

  it("joins the pack catalog on manifest_pack_id for the enable switch", () => {
    const packs = buildInstalledPacks(
      [run({ id: "a", pack_id: "hpack_win", rule_stats: {} })],
      null,
      [
        catalogEntry({
          pack_id: "windows_baseline",
          manifest_pack_id: "hpack_win",
          enabled: false,
        }),
      ],
    );
    expect(packs).toHaveLength(1);
    expect(packs[0]!.install_key).toBe("windows_baseline");
    expect(packs[0]!.enabled).toBe(false);
  });

  it("lists a shipped pack that has never run so it can be enabled", () => {
    const packs = buildInstalledPacks([], null, [
      catalogEntry({
        pack_id: "identity",
        manifest_pack_id: "hpack_identity",
        name: "Identity Hunt Pack",
        enabled: false,
        default_enabled: false,
        rule_count: 11,
      }),
    ]);
    expect(packs.map((p) => p.pack_name)).toEqual(["Identity Hunt Pack"]);
    expect(packs[0]!.run_count).toBe(0);
    expect(packs[0]!.last_run).toBeNull();
    expect(packs[0]!.rule_count).toBe(11);
    expect(packs[0]!.enabled).toBe(false);
  });

  it("leaves a pack with history but no catalog entry untoggleable", () => {
    const packs = buildInstalledPacks(
      [run({ id: "a", pack_id: "cti-merged-x", pack_name: "CTI merged", rule_stats: {} })],
      null,
      [],
    );
    expect(packs[0]!.install_key).toBeNull();
    expect(packs[0]!.source).toBeNull();
    expect(packs[0]!.enabled).toBe(true);
  });

  it("carries the catalog source through so custom packs are distinguishable", () => {
    const packs = buildInstalledPacks(
      [run({ id: "a", pack_id: "hpack_custom1", pack_name: "Org Pack", rule_stats: {} })],
      null,
      [
        catalogEntry({
          pack_id: "hpack_custom1",
          manifest_pack_id: "hpack_custom1",
          name: "Org Pack",
          source: "custom",
          installed: true,
          default_enabled: false,
        }),
      ],
    );
    expect(packs[0]!.source).toBe("custom");
    // Custom packs are enabled by existence; the catalog says so.
    expect(packs[0]!.enabled).toBe(true);
    expect(packs[0]!.install_key).toBe("hpack_custom1");
  });

  it("lists an uploaded custom pack that has never run yet", () => {
    const packs = buildInstalledPacks([], null, [
      catalogEntry({
        pack_id: "hpack_custom2",
        manifest_pack_id: "hpack_custom2",
        name: "Fresh Upload",
        source: "custom",
        installed: true,
        default_enabled: false,
        rule_count: 3,
      }),
    ]);
    expect(packs.map((p) => p.pack_name)).toEqual(["Fresh Upload"]);
    expect(packs[0]!.source).toBe("custom");
    expect(packs[0]!.run_count).toBe(0);
    expect(packs[0]!.rule_count).toBe(3);
  });
});

describe("indexCatalog", () => {
  it("keys entries by the manifest id the run history carries", () => {
    const idx = indexCatalog([
      catalogEntry({ pack_id: "identity", manifest_pack_id: "hpack_identity" }),
    ]);
    expect(idx.get("hpack_identity")!.pack_id).toBe("identity");
    expect(idx.get("identity")).toBeUndefined();
  });
});

// --------------------------------------------------------------------------- //
// Store surface
// --------------------------------------------------------------------------- //

const mockListPackRuns = vi.fn();
const mockGetNoiseBaseline = vi.fn();
const mockListHuntPacks = vi.fn();
const mockSetHuntPackEnabled = vi.fn();

vi.mock("@/api/hunt", () => ({
  listPackRuns: (...a: unknown[]) => mockListPackRuns(...a),
  getNoiseBaseline: (...a: unknown[]) => mockGetNoiseBaseline(...a),
  listHuntPacks: (...a: unknown[]) => mockListHuntPacks(...a),
  setHuntPackEnabled: (...a: unknown[]) => mockSetHuntPackEnabled(...a),
}));

import { useHuntPacksStore } from "@/stores/huntPacksStore";

const CATALOG = catalogEntry({ pack_id: "windows_baseline", manifest_pack_id: "hpack_win" });

beforeEach(() => {
  vi.clearAllMocks();
  mockListHuntPacks.mockResolvedValue({ items: [], total: 0, default_packs: [] });
  useHuntPacksStore.setState({
    runs: [],
    baseline: null,
    catalog: [],
    selectedPackId: null,
    selectedRuleId: null,
    togglingPackId: null,
    isLoading: false,
    error: null,
  });
});

describe("useHuntPacksStore.fetchAll", () => {
  it("populates runs, baseline and the pack catalog from the API", async () => {
    const items = [run({ id: "x" })];
    mockListPackRuns.mockResolvedValueOnce({ items, total: 1 });
    mockGetNoiseBaseline.mockResolvedValueOnce(baseline([noisyRule("hpack_win", "ruleA")]));
    mockListHuntPacks.mockResolvedValueOnce({
      items: [CATALOG],
      total: 1,
      default_packs: ["windows_baseline"],
    });

    await useHuntPacksStore.getState().fetchAll();

    const { runs, baseline: bl, catalog, isLoading, error } = useHuntPacksStore.getState();
    expect(runs).toEqual(items);
    expect(bl!.items).toHaveLength(1);
    expect(catalog).toEqual([CATALOG]);
    expect(isLoading).toBe(false);
    expect(error).toBeNull();
  });

  it("tolerates a noise-baseline failure without blanking the page", async () => {
    mockListPackRuns.mockResolvedValueOnce({ items: [run({ id: "x" })], total: 1 });
    mockGetNoiseBaseline.mockRejectedValueOnce(new Error("baseline down"));

    await useHuntPacksStore.getState().fetchAll();

    const state = useHuntPacksStore.getState();
    expect(state.runs).toHaveLength(1);
    expect(state.baseline).toBeNull();
    expect(state.error).toBeNull();
  });

  it("tolerates a pack-catalog failure without blanking the page", async () => {
    mockListPackRuns.mockResolvedValueOnce({ items: [run({ id: "x" })], total: 1 });
    mockGetNoiseBaseline.mockResolvedValueOnce(baseline([]));
    mockListHuntPacks.mockRejectedValueOnce(new Error("catalog down"));

    await useHuntPacksStore.getState().fetchAll();

    const state = useHuntPacksStore.getState();
    expect(state.runs).toHaveLength(1);
    expect(state.catalog).toEqual([]);
    expect(state.error).toBeNull();
  });

  it("sets error state when pack-runs fails", async () => {
    mockListPackRuns.mockRejectedValueOnce(new Error("boom"));
    mockGetNoiseBaseline.mockResolvedValueOnce(baseline([]));

    await useHuntPacksStore.getState().fetchAll();

    expect(useHuntPacksStore.getState().error).toBeTruthy();
    expect(useHuntPacksStore.getState().isLoading).toBe(false);
  });
});

describe("useHuntPacksStore.togglePackEnabled", () => {
  it("persists the new state and splices the server's answer in", async () => {
    useHuntPacksStore.setState({ catalog: [CATALOG] });
    mockSetHuntPackEnabled.mockResolvedValueOnce({ ...CATALOG, enabled: false, installed: true });

    await useHuntPacksStore.getState().togglePackEnabled("windows_baseline", false);

    expect(mockSetHuntPackEnabled).toHaveBeenCalledWith("windows_baseline", false);
    const state = useHuntPacksStore.getState();
    expect(state.catalog[0]!.enabled).toBe(false);
    expect(state.catalog[0]!.installed).toBe(true);
    expect(state.togglingPackId).toBeNull();
    expect(state.error).toBeNull();
  });

  it("surfaces a failure (e.g. RBAC 403) instead of flipping local state", async () => {
    useHuntPacksStore.setState({ catalog: [CATALOG] });
    mockSetHuntPackEnabled.mockRejectedValueOnce(new Error("forbidden"));

    await useHuntPacksStore.getState().togglePackEnabled("windows_baseline", false);

    const state = useHuntPacksStore.getState();
    expect(state.catalog[0]!.enabled).toBe(true); // unchanged
    expect(state.error).toBeTruthy();
    expect(state.togglingPackId).toBeNull();
  });

  it("ignores a pack with no install key (not in the scheduled catalog)", async () => {
    await useHuntPacksStore.getState().togglePackEnabled(null, false);
    expect(mockSetHuntPackEnabled).not.toHaveBeenCalled();
  });
});

describe("useHuntPacksStore.selectRule", () => {
  it("sets and clears the selected rule id", () => {
    useHuntPacksStore.getState().selectRule("ruleA");
    expect(useHuntPacksStore.getState().selectedRuleId).toBe("ruleA");
    useHuntPacksStore.getState().selectRule(null);
    expect(useHuntPacksStore.getState().selectedRuleId).toBeNull();
  });
});
