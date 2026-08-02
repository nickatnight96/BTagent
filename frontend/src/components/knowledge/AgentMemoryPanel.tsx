import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import { Brain, Loader2, Plus, Search, Sparkles, Trash2, X } from "lucide-react";
import {
  MEMORY_KINDS,
  forgetMemory,
  recallMemories,
  recordMemory,
  type AgentMemory,
  type MemoryKind,
  type MemoryRecallMode,
} from "@/api/memory";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { NativeSelect } from "@/components/ds/native-select";
import { Textarea } from "@/components/ds/textarea";

/** memory:write is senior_analyst+ (#484 rbac): authoring a fact shapes what
 * every future investigation in the org recalls — and so does removing one,
 * which is why Forget sits behind the same gate as Record. */
const WRITE_ROLES = new Set<string>([
  UserRole.SENIOR_ANALYST,
  UserRole.INCIDENT_COMMANDER,
  UserRole.ADMIN,
]);

const KIND_STYLES: Record<string, string> = {
  entity_note: "border-sky-500/40 text-sky-300",
  decision: "border-violet-500/40 text-violet-300",
  learning: "border-emerald-500/40 text-emerald-300",
  observation: "border-amber-500/40 text-amber-300",
};

/** An investigation id, bare (`inv_…`, what the close hook writes) or
 * prefixed (`investigation:inv_…`). Consolidation merges sources with commas,
 * so a row can carry several. */
const INVESTIGATION_SOURCE_RE = /^(?:investigation:)?(inv_[A-Za-z0-9_-]+)$/;

interface SourceRef {
  raw: string;
  investigationId: string | null;
}

function parseSources(source: string): SourceRef[] {
  return source
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((raw) => ({ raw, investigationId: INVESTIGATION_SOURCE_RE.exec(raw)?.[1] ?? null }));
}

function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: string } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
  }
  return fallback;
}

/**
 * Agent Memory (#482) — what the agent has learned about this org.
 *
 * The store's write side runs itself: investigation close records entity
 * notes and decisions automatically, and recall is injected into every new
 * investigation's prompt. That makes three things load-bearing here:
 *
 * 1. **Forget.** A wrong remembered fact is recalled into EVERY future
 *    investigation, so an overwrite is not a correction — removal is. The
 *    server soft-deletes (the row survives, stamped superseded) and writes an
 *    audit-ledger entry, so the confirmation step in this UI guards a real,
 *    reviewable governance act rather than a destructive one.
 * 2. **Semantic search.** Recall is subject-exact by default; the search box
 *    sends `query=` so an analyst can find "what do we know about lateral
 *    movement on finance hosts" without knowing the subject handle. The panel
 *    states which mode answered, because an empty semantic result ("nothing
 *    similar") is a different fact than an empty listing ("nothing recorded").
 * 3. **Provenance.** A fact the agent captured at investigation close and one
 *    an analyst typed carry very different weight, so every row shows its
 *    kind, source (linked back to the investigation when the source IS one),
 *    confidence, TLP and last-updated.
 *
 * Recall is TLP-bounded server-side (≤ AMBER_STRICT); a RED memory never
 * reaches this panel regardless of role. An empty store renders explicitly —
 * "the agent has recorded nothing yet" is a real answer about a young
 * deployment, not a blank.
 */
export function AgentMemoryPanel() {
  const role = useAuthStore((s) => s.user?.role ?? null);
  const canWrite = role !== null && WRITE_ROLES.has(role);

  const [memories, setMemories] = useState<AgentMemory[] | null>(null);
  const [mode, setMode] = useState<MemoryRecallMode>("recency");
  const [subjectFilter, setSubjectFilter] = useState("");
  const [kindFilter, setKindFilter] = useState<"" | MemoryKind>("");

  // Semantic search. Held separately from the input so each keystroke does
  // not fire an embedding round-trip — the query is submitted deliberately.
  const [searchInput, setSearchInput] = useState("");
  const [query, setQuery] = useState("");

  // Record form (senior+).
  const [formOpen, setFormOpen] = useState(false);
  const [kind, setKind] = useState<MemoryKind>("entity_note");
  const [subject, setSubject] = useState("");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Forget: two-step, because recall shapes every future investigation.
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [forgetting, setForgetting] = useState(false);
  const [forgetError, setForgetError] = useState<string | null>(null);

  // F13: debounce the subject filter so a recall fires once the user pauses,
  // not on every keystroke (the semantic `query` is already gated behind a
  // submit). load() keys on the debounced value, not the raw input.
  const [debouncedSubject, setDebouncedSubject] = useState("");
  useEffect(() => {
    const handle = window.setTimeout(() => setDebouncedSubject(subjectFilter), 300);
    return () => window.clearTimeout(handle);
  }, [subjectFilter]);

  const load = useCallback(async () => {
    try {
      const resp = await recallMemories({
        subject: debouncedSubject.trim() || undefined,
        kind: kindFilter || undefined,
        query: query.trim() || undefined,
        limit: 50,
      });
      setMemories(resp.items);
      setMode(resp.mode ?? (query.trim() ? "semantic" : "recency"));
    } catch {
      // Self-effacing on failure, same as every panel: memory:read is
      // analyst+, so a 403 means the whole page is out of reach anyway.
      setMemories(null);
    }
  }, [debouncedSubject, kindFilter, query]);

  useEffect(() => {
    void load();
  }, [load]);

  if (memories === null) return null;

  const handleRecord = async () => {
    if (!subject.trim() || !content.trim()) {
      setFormError("Subject and content are both required.");
      return;
    }
    setFormError(null);
    setBusy(true);
    try {
      await recordMemory({ kind, subject: subject.trim(), content: content.trim() });
      setSubject("");
      setContent("");
      setFormOpen(false);
      await load();
    } catch (e) {
      setFormError(errMessage(e, "Could not record the memory."));
    } finally {
      setBusy(false);
    }
  };

  const handleForget = async (id: string) => {
    setForgetError(null);
    setForgetting(true);
    try {
      await forgetMemory(id);
      setConfirmId(null);
      // Reload rather than splice: the server decides what is still live.
      await load();
    } catch (e) {
      setForgetError(errMessage(e, "Could not forget the memory."));
    } finally {
      setForgetting(false);
    }
  };

  const filtered = Boolean(subjectFilter.trim() || kindFilter || query.trim());

  return (
    <section data-testid="agent-memory-panel">
      <div className="mb-3 flex items-center gap-2">
        <Brain className="h-4 w-4 text-purple-400" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-slate-100">Agent memory</h2>
        <span className="text-xs text-slate-400">
          facts the agent recalls into every new investigation
        </span>
        {canWrite && !formOpen && (
          <Button
            size="sm"
            variant="outline"
            className="ml-auto"
            onClick={() => setFormOpen(true)}
            data-testid="agent-memory-add"
          >
            <Plus className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            Record fact
          </Button>
        )}
      </div>

      {canWrite && formOpen && (
        <form
          className="mb-4 space-y-2 rounded-md border border-border bg-card/50 p-3"
          onSubmit={(e) => {
            e.preventDefault();
            void handleRecord();
          }}
          data-testid="agent-memory-form"
        >
          <div className="flex flex-wrap items-center gap-2">
            <NativeSelect
              value={kind}
              onChange={(e) => setKind(e.target.value as MemoryKind)}
              aria-label="Memory kind"
              data-testid="agent-memory-kind"
              className="h-9 w-40"
            >
              {MEMORY_KINDS.map((k) => (
                <option key={k} value={k}>
                  {k.replace("_", " ")}
                </option>
              ))}
            </NativeSelect>
            <Input
              value={subject}
              onChange={(e) => {
                setSubject(e.target.value);
                setFormError(null);
              }}
              placeholder="subject — e.g. host web-prod-03, vendor Acme"
              aria-label="Subject"
              data-testid="agent-memory-subject"
              className="h-9 flex-1 min-w-56"
            />
          </div>
          <Textarea
            value={content}
            onChange={(e) => {
              setContent(e.target.value);
              setFormError(null);
            }}
            placeholder="The fact itself. Recording the same kind + subject overwrites — that is how a wrong memory gets corrected."
            aria-label="Content"
            rows={3}
            data-testid="agent-memory-content"
            className="text-sm"
          />
          <div className="flex items-center gap-2">
            <Button type="submit" size="sm" disabled={busy} data-testid="agent-memory-submit">
              {busy ? (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <Plus className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
              )}
              Record
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={() => setFormOpen(false)}
              data-testid="agent-memory-cancel"
            >
              Cancel
            </Button>
            {formError && (
              <p
                className="text-xs text-severity-medium"
                role="alert"
                data-testid="agent-memory-error"
              >
                {formError}
              </p>
            )}
          </div>
        </form>
      )}

      {/* Semantic search — the server ranks by embedding similarity when a
       * query is sent, and falls back to recency if pgvector is unavailable. */}
      <form
        className="mb-2 flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setQuery(searchInput);
        }}
        data-testid="agent-memory-search-form"
      >
        <div className="relative flex-1 min-w-64">
          <Sparkles
            className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-400"
            aria-hidden="true"
          />
          <Input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search meaning, not just the subject — e.g. “lateral movement on finance hosts”"
            aria-label="Search memories"
            data-testid="agent-memory-search"
            className="h-9 w-full pl-7"
          />
        </div>
        <Button type="submit" size="sm" variant="outline" data-testid="agent-memory-search-submit">
          Search
        </Button>
        {query && (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => {
              setSearchInput("");
              setQuery("");
            }}
            data-testid="agent-memory-search-clear"
          >
            <X className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            Clear
          </Button>
        )}
        <span
          className="text-xs text-slate-500"
          data-testid="agent-memory-mode"
          title={
            mode === "semantic"
              ? "Ranked by embedding similarity to your query (falls back to recency if the vector index is unavailable)."
              : "Ranked most-recently-updated first; subject and kind match exactly."
          }
        >
          {mode === "semantic" ? "ranked by semantic similarity" : "ranked by recency / exact match"}
        </span>
      </form>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500"
            aria-hidden="true"
          />
          <Input
            value={subjectFilter}
            onChange={(e) => setSubjectFilter(e.target.value)}
            placeholder="Filter by subject…"
            aria-label="Filter by subject"
            data-testid="agent-memory-filter-subject"
            className="h-9 w-64 pl-7"
          />
        </div>
        <NativeSelect
          value={kindFilter}
          onChange={(e) => setKindFilter(e.target.value as "" | MemoryKind)}
          aria-label="Filter by kind"
          data-testid="agent-memory-filter-kind"
          className="h-9 w-40"
        >
          <option value="">all kinds</option>
          {MEMORY_KINDS.map((k) => (
            <option key={k} value={k}>
              {k.replace("_", " ")}
            </option>
          ))}
        </NativeSelect>
      </div>

      {forgetError && (
        <p
          className="mb-2 text-xs text-severity-medium"
          role="alert"
          data-testid="agent-memory-forget-error"
        >
          {forgetError}
        </p>
      )}

      {memories.length === 0 ? (
        <p className="text-sm text-slate-400" data-testid="agent-memory-empty">
          {query.trim()
            ? "No memory is semantically close to that query."
            : filtered
              ? "No memories match the filter."
              : "The agent has recorded nothing about this organisation yet — memories accrue as investigations close."}
        </p>
      ) : (
        <ul className="space-y-2" data-testid="agent-memory-list">
          {memories.map((m) => {
            const sources = parseSources(m.source);
            const autoCaptured = sources.some((s) => s.investigationId !== null);
            return (
              <li
                key={m.id}
                className="rounded-md border border-border bg-card/50 px-3 py-2"
                data-testid={`agent-memory-${m.id}`}
              >
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                      KIND_STYLES[m.kind] ?? "border-border text-muted-foreground"
                    }`}
                  >
                    {m.kind.replace("_", " ")}
                  </span>
                  <span className="font-medium text-slate-200">{m.subject}</span>
                  {/* Provenance: an auto-captured fact and a hand-entered one
                   * carry different weight — say which this is. */}
                  <span
                    className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                    data-testid={`agent-memory-origin-${m.id}`}
                    title={
                      autoCaptured
                        ? "Captured automatically when an investigation closed."
                        : "Entered by an analyst (or another non-investigation source)."
                    }
                  >
                    {autoCaptured ? "auto-captured" : "analyst-entered"}
                  </span>
                  {m.confidence !== null && (
                    <span className="text-slate-500">
                      {Math.round(m.confidence * 100)}% confidence
                    </span>
                  )}
                  <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                    TLP:{m.tlp_level}
                  </span>
                  <span
                    className="ml-auto shrink-0 text-slate-500"
                    title={m.created_at ? `first recorded ${new Date(m.created_at).toLocaleString()}` : undefined}
                  >
                    {m.updated_at ? `updated ${new Date(m.updated_at).toLocaleString()}` : ""}
                  </span>
                  {canWrite && confirmId !== m.id && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-2 text-slate-400 hover:text-severity-high"
                      onClick={() => {
                        setForgetError(null);
                        setConfirmId(m.id);
                      }}
                      data-testid={`agent-memory-forget-${m.id}`}
                      aria-label={`Forget memory about ${m.subject}`}
                    >
                      <Trash2 className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                      Forget
                    </Button>
                  )}
                </div>
                <p className="mt-1 text-sm text-slate-300">{m.content}</p>
                {sources.length > 0 && (
                  <p className="mt-0.5 text-xs text-slate-500">
                    source:{" "}
                    {sources.map((s, i) => (
                      <span key={`${m.id}-src-${s.raw}`}>
                        {i > 0 && ", "}
                        {s.investigationId ? (
                          // F13: client-side navigation — a raw <a href> forced
                          // a full-page reload out of the SPA.
                          <Link
                            className="text-blue-400 hover:underline"
                            to={`/investigations/${s.investigationId}`}
                            data-testid={`agent-memory-source-link-${m.id}`}
                          >
                            {s.raw}
                          </Link>
                        ) : (
                          s.raw
                        )}
                      </span>
                    ))}
                  </p>
                )}
                {canWrite && confirmId === m.id && (
                  <div
                    className="mt-2 flex flex-wrap items-center gap-2 rounded border border-severity-high/40 bg-severity-high/5 px-2 py-1.5"
                    data-testid={`agent-memory-forget-confirm-panel-${m.id}`}
                  >
                    <span className="text-xs text-slate-300">
                      Forget this fact? It stops being recalled into new investigations. The
                      removal is logged to the audit ledger.
                    </span>
                    <Button
                      size="sm"
                      variant="destructive"
                      className="h-7"
                      disabled={forgetting}
                      onClick={() => void handleForget(m.id)}
                      data-testid={`agent-memory-forget-confirm-${m.id}`}
                    >
                      {forgetting && (
                        <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                      )}
                      Forget it
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7"
                      disabled={forgetting}
                      onClick={() => setConfirmId(null)}
                      data-testid={`agent-memory-forget-cancel-${m.id}`}
                    >
                      Keep
                    </Button>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
