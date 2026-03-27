import { useNavigate } from "react-router-dom";
import { Clock, User } from "lucide-react";
import type { Investigation } from "@/types/investigation";
import { Card } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";

interface InvestigationCardProps {
  investigation: Investigation;
}

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

export function InvestigationCard({ investigation }: InvestigationCardProps) {
  const navigate = useNavigate();

  return (
    <Card
      hoverable
      onClick={() => navigate(`/investigations/${investigation.id}`)}
      className="group"
    >
      {/* Header row: severity + status */}
      <div className="flex items-center justify-between mb-3">
        <SeverityBadge severity={investigation.severity} />
        <StatusBadge status={investigation.status} />
      </div>

      {/* Title */}
      <h3 className="text-slate-100 font-semibold text-sm leading-snug group-hover:text-blue-400 transition-colors mb-1.5 line-clamp-2">
        {investigation.title}
      </h3>

      {/* Description */}
      {investigation.description && (
        <p className="text-slate-400 text-xs leading-relaxed line-clamp-2 mb-3">
          {investigation.description}
        </p>
      )}

      {/* Tags */}
      {investigation.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {investigation.tags.slice(0, 3).map((tag) => (
            <span
              key={tag}
              className="px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-400 border border-slate-700/50"
            >
              {tag}
            </span>
          ))}
          {investigation.tags.length > 3 && (
            <span className="px-1.5 py-0.5 text-[10px] rounded text-slate-500">
              +{investigation.tags.length - 3}
            </span>
          )}
        </div>
      )}

      {/* Footer: meta info */}
      <div className="flex items-center justify-between pt-3 border-t border-slate-700/30">
        <div className="flex items-center gap-1.5 text-xs text-slate-500">
          <Clock className="w-3.5 h-3.5" />
          <span>{formatRelativeTime(investigation.created_at)}</span>
        </div>
        {investigation.assigned_to && (
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <User className="w-3.5 h-3.5" />
            <span>{investigation.assigned_to}</span>
          </div>
        )}
      </div>

      {/* IOC and cost indicators */}
      <div className="flex items-center gap-3 mt-2">
        {investigation.iocs.length > 0 && (
          <span className="text-[10px] text-slate-500">
            {investigation.iocs.length} IOCs
          </span>
        )}
        {investigation.cost_usd > 0 && (
          <span className="text-[10px] text-slate-500">
            ${investigation.cost_usd.toFixed(2)}
          </span>
        )}
      </div>
    </Card>
  );
}
