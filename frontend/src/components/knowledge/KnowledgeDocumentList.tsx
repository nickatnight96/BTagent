import { useEffect } from "react";
import { FileText, Trash2, ChevronLeft, ChevronRight } from "lucide-react";
import { clsx } from "clsx";
import { useKnowledgeStore } from "@/stores/knowledgeStore";
import type { KnowledgeSourceType } from "@/types/knowledge";
import { SOURCE_TYPE_CONFIG } from "@/types/knowledge";

const badgeColorMap: Record<string, string> = {
  blue: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  green: "bg-green-500/20 text-green-300 border-green-500/30",
  red: "bg-red-500/20 text-red-300 border-red-500/30",
  purple: "bg-purple-500/20 text-purple-300 border-purple-500/30",
  yellow: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  orange: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  slate: "bg-slate-500/20 text-slate-300 border-slate-500/30",
};

function SourceBadge({ sourceType }: { sourceType: string }) {
  const config = SOURCE_TYPE_CONFIG[sourceType as KnowledgeSourceType];
  const colorClasses = config
    ? badgeColorMap[config.color] ?? badgeColorMap.slate
    : badgeColorMap.slate;
  const label = config?.label ?? sourceType;

  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border",
        colorClasses,
      )}
    >
      {label}
    </span>
  );
}

export function KnowledgeDocumentList() {
  const {
    documents,
    totalDocuments,
    documentsPage,
    documentsPageSize,
    isLoading,
    fetchDocuments,
    deleteDocument,
  } = useKnowledgeStore();

  useEffect(() => {
    void fetchDocuments();
  }, [fetchDocuments]);

  const totalPages = Math.ceil(totalDocuments / documentsPageSize);

  const handlePrev = () => {
    if (documentsPage > 1) {
      void fetchDocuments({ page: documentsPage - 1 });
    }
  };

  const handleNext = () => {
    if (documentsPage < totalPages) {
      void fetchDocuments({ page: documentsPage + 1 });
    }
  };

  const handleDelete = async (id: string) => {
    if (window.confirm("Delete this document and all its chunks? This cannot be undone.")) {
      await deleteDocument(id);
    }
  };

  return (
    <div className="space-y-4" data-testid="knowledge-list">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300">
          Documents ({totalDocuments})
        </h3>
      </div>

      {isLoading && documents.length === 0 ? (
        <div
          className="text-center py-8 text-slate-500"
          data-testid="knowledge-list-loading"
        >
          Loading documents...
        </div>
      ) : documents.length === 0 ? (
        <div
          className="text-center py-8 text-slate-500"
          data-testid="knowledge-list-empty"
        >
          No documents in the knowledge base yet.
        </div>
      ) : (
        <div className="space-y-2" data-testid="knowledge-list-items">
          {documents.map((doc) => (
            <div
              key={doc.id}
              className="flex items-center gap-3 p-3 bg-slate-800 border border-slate-700/50 rounded-lg hover:border-slate-600 transition-colors"
              data-testid={`knowledge-doc-${doc.id}`}
            >
              <FileText
                className="w-5 h-5 text-slate-400 shrink-0"
                aria-hidden="true"
              />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-slate-200 truncate">
                    {doc.title}
                  </span>
                  <SourceBadge sourceType={doc.source_type} />
                </div>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-xs text-slate-500">
                    {(doc.token_count ?? 0).toLocaleString()} tokens
                  </span>
                  {doc.created_at && (
                    <span className="text-xs text-slate-500">
                      {new Date(doc.created_at).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => void handleDelete(doc.id)}
                className="p-1.5 text-slate-500 hover:text-red-400 rounded transition-colors"
                title="Delete document"
                aria-label={`Delete document ${doc.title}`}
                data-testid={`knowledge-doc-${doc.id}-delete-button`}
              >
                <Trash2 className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div
          className="flex items-center justify-between pt-2"
          data-testid="knowledge-list-pagination"
        >
          <span className="text-xs text-slate-500">
            Page {documentsPage} of {totalPages}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={handlePrev}
              disabled={documentsPage <= 1}
              className="p-1.5 rounded text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed"
              aria-label="Previous page"
              data-testid="knowledge-list-prev-button"
            >
              <ChevronLeft className="w-4 h-4" aria-hidden="true" />
            </button>
            <button
              onClick={handleNext}
              disabled={documentsPage >= totalPages}
              className="p-1.5 rounded text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed"
              aria-label="Next page"
              data-testid="knowledge-list-next-button"
            >
              <ChevronRight className="w-4 h-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
