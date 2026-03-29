import { DollarSign } from "lucide-react";
import { useState } from "react";

interface CostBadgeProps {
  costUsd?: number | null;
  tokenCount?: number | null;
}

export function CostBadge({ costUsd, tokenCount }: CostBadgeProps) {
  const [showTooltip, setShowTooltip] = useState(false);

  const safeCost = costUsd ?? 0;
  const safeTokens = tokenCount ?? 0;

  const formattedCost =
    safeCost < 0.01 ? "<$0.01" : `$${safeCost.toFixed(2)}`;

  const formattedTokens =
    safeTokens >= 1_000_000
      ? `${(safeTokens / 1_000_000).toFixed(1)}M tokens`
      : safeTokens >= 1000
        ? `${(safeTokens / 1000).toFixed(1)}K tokens`
        : `${safeTokens} tokens`;

  return (
    <div
      className="relative inline-flex"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
        <DollarSign className="w-3 h-3" />
        {formattedCost}
      </span>

      {/* Tooltip */}
      {showTooltip && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-1.5 bg-slate-800 border border-slate-600/50 rounded-md shadow-lg text-xs text-slate-300 whitespace-nowrap z-50">
          <div>{formattedTokens}</div>
          <div className="text-slate-500">
            Cost: ${safeCost.toFixed(4)}
          </div>
          {/* Arrow */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 w-2 h-2 bg-slate-800 border-r border-b border-slate-600/50 rotate-45 -mt-1" />
        </div>
      )}
    </div>
  );
}
