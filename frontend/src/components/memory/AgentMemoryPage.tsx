import { Brain } from "lucide-react";
import { AgentMemoryPanel } from "@/components/knowledge/AgentMemoryPanel";

/**
 * Agent Memory — its own surface (#482 follow-up).
 *
 * The store was previously reachable only as a panel at the bottom of the
 * Knowledge Base page, which understated it: this is not a corner of the RAG
 * corpus, it is the set of facts injected into every new investigation's
 * prompt. Anything an analyst is expected to audit and correct needs its own
 * entry in the nav, so a wrong remembered fact is discoverable before it has
 * shaped ten more cases.
 *
 * The header renders unconditionally; the panel below hides itself if recall
 * fails (403/outage), so the page still explains what this surface is.
 */
export function AgentMemoryPage() {
  return (
    <div className="flex flex-col h-full" data-testid="agent-memory-page">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700/50">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-purple-600/20 border border-purple-500/30">
          <Brain className="w-4 h-4 text-purple-400" aria-hidden="true" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Agent Memory</h1>
          <p className="text-sm text-slate-400">
            What the agent has learned about this organisation — recalled into every new
            investigation. Search it, correct it, or forget a fact that is wrong.
          </p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-4xl mx-auto">
          <AgentMemoryPanel />
        </div>
      </div>
    </div>
  );
}
