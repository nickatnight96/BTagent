import { useState, useCallback } from "react";
import { X, Upload } from "lucide-react";
import { useKnowledgeStore } from "@/stores/knowledgeStore";
import type { KnowledgeSourceType } from "@/types/knowledge";
import { SOURCE_TYPE_CONFIG } from "@/types/knowledge";

const SOURCE_TYPES = Object.keys(SOURCE_TYPE_CONFIG) as KnowledgeSourceType[];

interface KnowledgeIngestModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function KnowledgeIngestModal({ isOpen, onClose }: KnowledgeIngestModalProps) {
  const { ingest, isIngesting } = useKnowledgeStore();

  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [sourceType, setSourceType] = useState<KnowledgeSourceType>("runbook");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      setSuccess(false);

      if (!title.trim() || !content.trim()) {
        setError("Title and content are required.");
        return;
      }

      try {
        await ingest(title, content, sourceType);
        setSuccess(true);
        setTitle("");
        setContent("");
        setTimeout(() => {
          onClose();
          setSuccess(false);
        }, 1500);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Ingest failed");
      }
    },
    [title, content, sourceType, ingest, onClose],
  );

  const handleFileUpload = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;

      const text = await file.text();
      setContent(text);
      if (!title.trim()) {
        setTitle(file.name.replace(/\.[^.]+$/, ""));
      }
    },
    [title],
  );

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="knowledge-ingest-title"
      data-testid="knowledge-ingest-dialog"
    >
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
          <h2
            id="knowledge-ingest-title"
            className="text-lg font-semibold text-slate-100"
          >
            Ingest Document
          </h2>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-200 rounded transition-colors"
            aria-label="Close ingest dialog"
            data-testid="knowledge-ingest-close-button"
          >
            <X className="w-5 h-5" aria-hidden="true" />
          </button>
        </div>

        {/* Body */}
        <form
          onSubmit={handleSubmit}
          className="px-6 py-4 space-y-4"
          data-testid="knowledge-ingest-form"
        >
          {/* Title */}
          <div>
            <label
              htmlFor="knowledge-ingest-title-input"
              className="block text-sm font-medium text-slate-300 mb-1"
            >
              Title
            </label>
            <input
              id="knowledge-ingest-title-input"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Document title"
              className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              data-testid="knowledge-ingest-title-input"
            />
          </div>

          {/* Source type */}
          <div>
            <label
              htmlFor="knowledge-ingest-source-input"
              className="block text-sm font-medium text-slate-300 mb-1"
            >
              Source Type
            </label>
            <select
              id="knowledge-ingest-source-input"
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value as KnowledgeSourceType)}
              className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
              data-testid="knowledge-ingest-source-input"
            >
              {SOURCE_TYPES.map((type) => (
                <option key={type} value={type}>
                  {SOURCE_TYPE_CONFIG[type].label}
                </option>
              ))}
            </select>
          </div>

          {/* File upload */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">
              Upload File (optional)
            </label>
            <label className="flex items-center gap-2 px-3 py-2 bg-slate-800 border border-dashed border-slate-600 rounded-lg cursor-pointer hover:border-slate-500 transition-colors">
              <Upload className="w-4 h-4 text-slate-400" aria-hidden="true" />
              <span className="text-sm text-slate-400">
                Click to upload a text file
              </span>
              <input
                type="file"
                accept=".txt,.md,.json,.yaml,.yml,.csv"
                onChange={handleFileUpload}
                className="hidden"
                aria-label="Upload knowledge document file"
                data-testid="knowledge-ingest-file-input"
              />
            </label>
          </div>

          {/* Content */}
          <div>
            <label
              htmlFor="knowledge-ingest-content-input"
              className="block text-sm font-medium text-slate-300 mb-1"
            >
              Content
            </label>
            <textarea
              id="knowledge-ingest-content-input"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste document content here..."
              rows={10}
              className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 resize-y font-mono text-sm"
              data-testid="knowledge-ingest-content-input"
            />
          </div>

          {/* Error */}
          {error && (
            <div
              className="p-3 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm"
              role="alert"
              data-testid="knowledge-ingest-error"
            >
              {error}
            </div>
          )}

          {/* Success */}
          {success && (
            <div
              className="p-3 bg-green-900/20 border border-green-500/30 rounded-lg text-green-400 text-sm"
              role="status"
              data-testid="knowledge-ingest-success"
            >
              Document ingested successfully!
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
              data-testid="knowledge-ingest-cancel-button"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isIngesting || !title.trim() || !content.trim()}
              className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              data-testid="knowledge-ingest-submit-button"
            >
              {isIngesting ? "Ingesting..." : "Ingest Document"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
