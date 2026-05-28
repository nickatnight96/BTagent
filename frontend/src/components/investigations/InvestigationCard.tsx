import { useNavigate } from "react-router-dom";
import { Clock, User } from "lucide-react";
import type { Investigation } from "@/types/investigation";
import { Card } from "@/components/ds/card";
import { SeverityBadge } from "@/components/ds/severity-badge";
import { StatusBadge } from "@/components/ds/status-badge";

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
      onClick={() => navigate(`/investigations/${investigation.id}`)}
      className="group p-4 cursor-pointer transition-all hover:border-primary/40 hover:shadow-md focus-within:ring-2 focus-within:ring-ring"
      role="link"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          navigate(`/investigations/${investigation.id}`);
        }
      }}
      aria-label={`Open investigation ${investigation.title}`}
      data-testid={`investigation-card-${investigation.id}`}
    >
      {/* Header row: severity + status */}
      <div className="flex items-center justify-between mb-3">
        <SeverityBadge severity={investigation.severity} />
        <StatusBadge status={investigation.status} />
      </div>

      {/* Title */}
      <h3 className="text-foreground font-semibold text-sm leading-snug group-hover:text-primary transition-colors mb-1.5 line-clamp-2">
        {investigation.title}
      </h3>

      {/* Description */}
      {investigation.description && (
        <p className="text-muted-foreground text-xs leading-relaxed line-clamp-2 mb-3">
          {investigation.description}
        </p>
      )}

      {/* Tags */}
      {(investigation.tags ?? []).length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {(investigation.tags ?? []).slice(0, 3).map((tag) => (
            <span
              key={tag}
              className="px-1.5 py-0.5 text-[10px] rounded bg-accent text-muted-foreground border border-border/50"
            >
              {tag}
            </span>
          ))}
          {(investigation.tags ?? []).length > 3 && (
            <span className="px-1.5 py-0.5 text-[10px] rounded text-muted-foreground">
              +{(investigation.tags ?? []).length - 3}
            </span>
          )}
        </div>
      )}

      {/* Footer: meta info */}
      <div className="flex items-center justify-between pt-3 border-t border-border/30">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Clock className="w-3.5 h-3.5" />
          <span>{formatRelativeTime(investigation.created_at)}</span>
        </div>
        {investigation.assigned_to && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <User className="w-3.5 h-3.5" />
            <span>{investigation.assigned_to}</span>
          </div>
        )}
      </div>

      {/* IOC and cost indicators */}
      <div className="flex items-center gap-3 mt-2">
        {(investigation.iocs ?? []).length > 0 && (
          <span className="text-[10px] text-muted-foreground">
            {(investigation.iocs ?? []).length} IOCs
          </span>
        )}
        {(investigation.cost_usd ?? 0) > 0 && (
          <span className="text-[10px] text-muted-foreground">
            ${(investigation.cost_usd ?? 0).toFixed(2)}
          </span>
        )}
      </div>
    </Card>
  );
}
