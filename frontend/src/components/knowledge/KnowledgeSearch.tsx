import { useState, useCallback } from "react";
import { Search, Filter, X } from "lucide-react";
import { clsx } from "clsx";
import { useKnowledgeStore } from "@/stores/knowledgeStore";
import type { KnowledgeSourceType } from "@/types/knowledge";
import { SOURCE_TYPE_CONFIG } from "@/types/knowledge";

const SOURCE_TYPES = Object.keys(SOURCE_TYPE_CONFIG) as KnowledgeSourceType[];

export function KnowledgeSearch() {
  const {
    searchQuery,
    searchResults,
    totalResults,
    isSearching,
    sourceFilter,
    error,
    hybridSearch,
    setSourceFilter,
    setSearchQuery,
    clearSearch,
    clearError,
  } = useKnowledgeStore();

  const [localQuery, setLocalQuery] = useState(searchQuery);
  const [showFilters, setShowFilters] = useState(false);

  const handleSearch = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!localQuery.trim()) return;
      await hybridSearch(localQuery, 10, sourceFilter ?? undefined);
    },
    [localQuery, sourceFilter, hybridSearch],
  );

  const handleClear = useCallback(() => {
    setLocalQuery("");
    clearSearch();
  }, [clearSearch]);

  const highlightSnippet = (text: string, query: string) => {
    if (!query.trim()) return text;
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi");
    const parts = text.split(regex);
    return parts.map((part, i) =>
      regex.test(part) ? (
        <mark key={i} className="bg-yellow-500/30 text-yellow-200 rounded px-0.5">
          {part}
        </mark>
      ) : (
        part
      ),
    );
  };

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <form onSubmit={handleSearch} className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            value={localQuery}
            onChange={(e) => {
              setLocalQuery(e.target.value);
              setSearchQuery(e.target.value);
            }}
            placeholder="Search knowledge base..."
            className="w-full pl-10 pr-10 py-2.5 bg-slate-800 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          {localQuery && (
            <button
              type="button"
              onClick={handleClear}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        <button
          type="button"
          onClick={() => setShowFilters(!showFilters)}
          className={clsx(
            "px-3 py-2.5 rounded-lg border transition-colors",
            showFilters
              ? "bg-blue-600/20 border-blue-500/30 text-blue-400"
              : "bg-slate-800 border-slate-600 text-slate-400 hover:text-slate-200",
          )}
        >
          <Filter className="w-4 h-4" />
        </button>
        <button
          type="submit"
          disabled={isSearching || !localQuery.trim()}
          className="px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isSearching ? "Searching..." : "Search"}
        </button>
      </form>

      {/* Source type filter */}
      {showFilters && (
        <div className="flex flex-wrap gap-2 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
          <button
            onClick={() => setSourceFilter(null)}
            className={clsx(
              "px-3 py-1.5 rounded-full text-xs font-medium transition-colors",
              sourceFilter === null
                ? "bg-blue-600/30 text-blue-300 border border-blue-500/30"
                : "bg-slate-700 text-slate-400 hover:text-slate-200",
            )}
          >
            All Sources
          </button>
          {SOURCE_TYPES.map((type) => {
            const config = SOURCE_TYPE_CONFIG[type];
            return (
              <button
                key={type}
                onClick={() => setSourceFilter(type)}
                className={clsx(
                  "px-3 py-1.5 rounded-full text-xs font-medium transition-colors",
                  sourceFilter === type
                    ? "bg-blue-600/30 text-blue-300 border border-blue-500/30"
                    : "bg-slate-700 text-slate-400 hover:text-slate-200",
                )}
              >
                {config.label}
              </button>
            );
          })}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="p-3 bg-red-900/20 border border-red-500/30 rounded-lg flex items-center justify-between">
          <span className="text-red-400 text-sm">{error}</span>
          <button onClick={clearError} className="text-red-400 hover:text-red-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Results */}
      {searchResults.length > 0 && (
        <div className="space-y-3">
          <p className="text-sm text-slate-400">
            {totalResults} result{totalResults !== 1 ? "s" : ""} for &quot;{searchQuery}&quot;
          </p>
          {searchResults.map((result, i) => (
            <div
              key={`${result.chunk_id}-${i}`}
              className="p-4 bg-slate-800 border border-slate-700/50 rounded-lg hover:border-slate-600 transition-colors"
            >
              <div className="flex items-center gap-2 mb-2">
                <span className="text-sm font-medium text-slate-200">
                  {result.document_title}
                </span>
                <span className="px-2 py-0.5 rounded-full text-xs bg-slate-700 text-slate-300">
                  {SOURCE_TYPE_CONFIG[result.source_type as KnowledgeSourceType]?.label ??
                    result.source_type}
                </span>
                <span className="text-xs text-slate-500 ml-auto">
                  Score: {(result.relevance_score ?? 0).toFixed(4)}
                </span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed line-clamp-3">
                {highlightSnippet(result.chunk_content, searchQuery)}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {searchQuery && !isSearching && searchResults.length === 0 && (
        <div className="text-center py-8 text-slate-500">
          No results found for &quot;{searchQuery}&quot;
        </div>
      )}
    </div>
  );
}
