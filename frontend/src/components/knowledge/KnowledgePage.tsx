import { useState } from "react";
import { BookOpen, Plus } from "lucide-react";
import { KnowledgeSearch } from "./KnowledgeSearch";
import { KnowledgeDocumentList } from "./KnowledgeDocumentList";
import { KnowledgeIngestModal } from "./KnowledgeIngestModal";

export function KnowledgePage() {
  const [showIngestModal, setShowIngestModal] = useState(false);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/50">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-purple-600/20 border border-purple-500/30">
            <BookOpen className="w-4 h-4 text-purple-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-100">Knowledge Base</h1>
            <p className="text-sm text-slate-400">
              Search, browse, and ingest security knowledge
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowIngestModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Ingest Document
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-4xl mx-auto space-y-8">
          {/* Search */}
          <section>
            <KnowledgeSearch />
          </section>

          {/* Document list */}
          <section>
            <KnowledgeDocumentList />
          </section>
        </div>
      </div>

      {/* Ingest modal */}
      <KnowledgeIngestModal
        isOpen={showIngestModal}
        onClose={() => setShowIngestModal(false)}
      />
    </div>
  );
}
