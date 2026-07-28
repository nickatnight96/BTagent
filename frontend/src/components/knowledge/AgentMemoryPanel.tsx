import { useCallback, useEffect, useState } from "react";
import { Brain, Loader2, Plus, Search } from "lucide-react";
import {
  MEMORY_KINDS,
  recallMemories,
  recordMemory,
  type AgentMemory,
  type MemoryKind,
} from "@/api/memory";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { NativeSelect } from "@/components/ds/native-select";
import { Textarea } from "@/components/ds/textarea";

/** memory:write is senior_analyst+ (#484 rbac): authoring a fact shapes what
 * every future investigation in the org recalls. */
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

function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: string } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
  }
  return fallback;
}

/**
 * Agent Memory (#482/#484) — what the agent has learned about this org.
 *
 * The store's write side runs itself: investigation close records entity
 * notes and decisions automatically, and recall is injected into every new
 * investigation's prompt. Until now none of it was visible, which cuts both
 * ways: analysts couldn't see what the agent "believes" about their
 * environment, and a wrong remembered fact — recalled into every future
 * investigation — could only be corrected over curl. The record form is that
 * correction path: recording the same kind+subject overwrites (upsert), so
 * fixing a bad memory is writing the right one over it.
 *
 * Recall here is TLP-bounded server-side (≤ AMBER_STRICT); a RED memory
 * never reaches this panel regardless of role. An empty store renders
 * explicitly — "the agent has recorded nothing yet" is a real answer about a
 * young deployment, not a blank.
 */
export function AgentMemoryPanel() {
  const role = useAuthStore((s) => s.user?.role ?? null);
  const canWrite = role !== null && WRITE_ROLES.has(role);

  const [memories, setMemories] = useState<AgentMemory[] | null>(null);
  const [subjectFilter, setSubjectFilter] = useState("");
  const [kindFilter, setKindFilter] = useState<"" | MemoryKind>("");

  // Record form (senior+).
  const [formOpen, setFormOpen] = useState(false);
  const [kind, setKind] = useState<MemoryKind>("entity_note");
  const [subject, setSubject] = useState("");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const resp = await recallMemories({
        subject: subjectFilter.trim() || undefined,
        kind: kindFilter || undefined,
        limit: 50,
      });
      setMemories(resp.items);
    } catch {
      // Self-effacing on failure, same as every panel: memory:read is
      // analyst+, so a 403 means the whole page is out of reach anyway.
      setMemories(null);
    }
  }, [subjectFilter, kindFilter]);

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

      {memories.length === 0 ? (
        <p className="text-sm text-slate-400" data-testid="agent-memory-empty">
          {subjectFilter.trim() || kindFilter
            ? "No memories match the filter."
            : "The agent has recorded nothing about this organisation yet — memories accrue as investigations close."}
        </p>
      ) : (
        <ul className="space-y-2" data-testid="agent-memory-list">
          {memories.map((m) => (
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
                {m.confidence !== null && (
                  <span className="text-slate-500">
                    {Math.round(m.confidence * 100)}% confidence
                  </span>
                )}
                <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                  TLP:{m.tlp_level}
                </span>
                <span className="ml-auto shrink-0 text-slate-500">
                  {m.updated_at ? new Date(m.updated_at).toLocaleString() : ""}
                </span>
              </div>
              <p className="mt-1 text-sm text-slate-300">{m.content}</p>
              {m.source && (
                <p className="mt-0.5 text-xs text-slate-500">source: {m.source}</p>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
