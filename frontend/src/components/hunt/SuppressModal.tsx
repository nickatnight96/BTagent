import { useState } from "react";
import { X, ShieldOff } from "lucide-react";
import type { HuntFinding, SuppressionMatch } from "@/types/hunt";
import { useHuntStore } from "@/stores/huntStore";

interface SuppressModalProps {
  finding: HuntFinding | null;
  onClose: () => void;
}

/** Build the default suppression criteria from a finding's own shape. */
function defaultMatch(finding: HuntFinding): SuppressionMatch {
  return {
    source: finding.source,
    domain: null,
    technique_ids: [...finding.technique_ids],
    entity_values: [],
    observable_values: [],
  };
}

export function SuppressModal({ finding, onClose }: SuppressModalProps) {
  const suppress = useHuntStore((s) => s.suppress);
  const isMutating = useHuntStore((s) => s.isMutating);
  const error = useHuntStore((s) => s.error);

  const [name, setName] = useState("");
  const [reason, setReason] = useState("");
  const [reconfirmDays, setReconfirmDays] = useState(90);

  if (!finding) return null;

  const match = defaultMatch(finding);

  const handleSubmit = async () => {
    try {
      await suppress(finding.id, {
        name: name.trim(),
        reason: reason.trim(),
        match,
        reconfirm_in_hours: reconfirmDays * 24,
      });
      onClose();
    } catch {
      // error surfaced via store.error
    }
  };

  const canSubmit = name.trim().length > 0 && reason.trim().length > 0 && !isMutating;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      data-testid="hunt-suppress-modal"
    >
      <div className="w-full max-w-lg rounded-xl bg-slate-900 border border-slate-700 shadow-xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700/50">
          <div className="flex items-center gap-2">
            <ShieldOff className="w-4 h-4 text-amber-400" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-100">Suppress finding</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Rule name</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Approved admin tooling on jump hosts"
              className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
              data-testid="hunt-suppress-name"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Reason (audit trail)
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder="Why is this expected / benign?"
              className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
              data-testid="hunt-suppress-reason"
            />
          </div>

          <div>
            <span className="block text-xs font-medium text-slate-400 mb-1">
              Matches (derived from this finding)
            </span>
            <div className="flex flex-wrap gap-1.5">
              {match.source && (
                <span className="px-2 py-0.5 rounded-full text-xs bg-slate-700/50 text-slate-300 border border-slate-600/50">
                  source: {match.source}
                </span>
              )}
              {match.technique_ids.map((t) => (
                <span
                  key={t}
                  className="px-2 py-0.5 rounded-full text-xs bg-blue-500/10 text-blue-300 border border-blue-500/20"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Re-confirm after (days)
            </label>
            <input
              type="number"
              min={1}
              max={365}
              value={reconfirmDays}
              onChange={(e) => setReconfirmDays(Number(e.target.value))}
              className="w-28 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
              data-testid="hunt-suppress-reconfirm"
            />
          </div>

          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>

        <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-slate-700/50">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-slate-100"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!canSubmit}
            className="px-4 py-2 bg-amber-600 text-white text-sm font-medium rounded-lg hover:bg-amber-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            data-testid="hunt-suppress-submit"
          >
            Suppress
          </button>
        </div>
      </div>
    </div>
  );
}
