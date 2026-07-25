import { useState } from "react";
import { Link } from "react-router-dom";
import { BookOpen, Loader2, Search, ExternalLink } from "lucide-react";
import { searchNotebook } from "@/api/iocs";
import type { IOC, IOCDisposition } from "@/types/ioc";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { NativeSelect } from "@/components/ds/native-select";
import { AnnotationBadges } from "./IOCNotebook";

const DISPOSITION_OPTIONS: { label: string; value: Exclude<IOCDisposition, ""> | "" }[] = [
  { label: "Any disposition", value: "" },
  { label: "Under review", value: "under_review" },
  { label: "Confirmed malicious", value: "confirmed_malicious" },
  { label: "Benign", value: "benign" },
  { label: "False positive", value: "false_positive" },
];

/**
 * Cross-case notebook search (#108 UC-5.2): "have we seen this before, and
 * what did we conclude?" — queries the annotated-IOC layer across all
 * accessible investigations (the q matches notes and tags, not just values)
 * and links each hit back to its parent case.
 */
export function NotebookSearchPanel() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [disposition, setDisposition] = useState<Exclude<IOCDisposition, ""> | "">("");
  const [results, setResults] = useState<IOC[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runSearch = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await searchNotebook(q, disposition || undefined);
      setResults(resp.items);
      setTotal(resp.total);
    } catch {
      setError("Notebook search failed");
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="mb-4 rounded-lg border border-border bg-card/50"
      data-testid="notebook-search-panel"
    >
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-4 py-2.5 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
        data-testid="notebook-search-toggle"
      >
        <BookOpen className="w-4 h-4 text-primary" aria-hidden="true" />
        Cross-case notebook search
        <span className="text-xs font-normal">
          — find annotated IOCs across all your cases
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4">
          <form
            className="flex flex-col sm:flex-row gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void runSearch();
            }}
          >
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search notes, tags, and values…"
              aria-label="Notebook search query"
              data-testid="notebook-search-input"
              className="flex-1"
            />
            <NativeSelect
              value={disposition}
              onChange={(e) =>
                setDisposition(e.target.value as Exclude<IOCDisposition, ""> | "")
              }
              aria-label="Filter by disposition"
              data-testid="notebook-search-disposition-select"
              className="sm:w-48"
            >
              {DISPOSITION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </NativeSelect>
            <Button type="submit" disabled={loading} data-testid="notebook-search-button">
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" aria-label="Searching" />
              ) : (
                <Search className="w-4 h-4" aria-hidden="true" />
              )}
              <span className="ml-2">Search</span>
            </Button>
          </form>

          {error && (
            <p className="mt-3 text-sm text-severity-medium" role="alert">
              {error}
            </p>
          )}

          {results !== null && !error && (
            <div className="mt-3" data-testid="notebook-search-results">
              {results.length === 0 ? (
                <p
                  className="text-sm text-muted-foreground"
                  data-testid="notebook-search-empty"
                >
                  No annotated IOCs match.
                </p>
              ) : (
                <>
                  <p className="text-xs text-muted-foreground mb-2">
                    {total} annotated IOC(s) across your cases
                  </p>
                  <ul className="divide-y divide-border">
                    {results.map((ioc) => (
                      <li
                        key={ioc.id}
                        className="py-2 flex items-start justify-between gap-3"
                        data-testid={`notebook-search-result-${ioc.id}`}
                      >
                        <div className="min-w-0">
                          <p className="text-sm font-mono truncate">{ioc.value}</p>
                          <AnnotationBadges ioc={ioc} />
                          {ioc.analyst_note && (
                            <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
                              {ioc.analyst_note}
                            </p>
                          )}
                        </div>
                        {ioc.investigation_id && (
                          <Link
                            to={`/investigations/${ioc.investigation_id}`}
                            className="shrink-0 inline-flex items-center gap-1 text-xs text-primary hover:underline"
                            data-testid={`notebook-search-case-link-${ioc.id}`}
                          >
                            Open case
                            <ExternalLink className="w-3 h-3" aria-hidden="true" />
                          </Link>
                        )}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
