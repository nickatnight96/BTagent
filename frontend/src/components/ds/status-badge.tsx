import { Badge } from "@/components/ds/badge";
import { cn } from "@/lib/utils";
import { InvestigationStatus } from "@/types/config";

const STATUS_TO_VARIANT: Record<
  InvestigationStatus,
  "default" | "secondary" | "destructive" | "outline" | "low" | "medium" | "info"
> = {
  [InvestigationStatus.PENDING]: "secondary",
  [InvestigationStatus.TRIAGING]: "low", // blue = agent working
  [InvestigationStatus.INVESTIGATING]: "low",
  [InvestigationStatus.PAUSED_HITL]: "medium", // yellow = needs human
  [InvestigationStatus.PAUSED]: "outline",
  [InvestigationStatus.CONTAINED]: "info",
  [InvestigationStatus.REMEDIATED]: "info",
  [InvestigationStatus.CLOSED]: "info",
  [InvestigationStatus.FAILED]: "destructive",
  [InvestigationStatus.CANCELLED]: "outline",
  [InvestigationStatus.ARCHIVED]: "secondary",
};

/**
 * Statuses where the agent is mid-flight or a human is blocking it — the ones
 * worth a pulsing dot. Everything else is at rest.
 */
const ACTIVE_STATUSES: readonly InvestigationStatus[] = [
  InvestigationStatus.TRIAGING,
  InvestigationStatus.INVESTIGATING,
  InvestigationStatus.PAUSED_HITL,
];

interface StatusBadgeProps {
  status: InvestigationStatus;
  className?: string;
  "data-testid"?: string;
}

/**
 * StatusBadge — maps an InvestigationStatus to a Badge variant and adds a
 * pulsing dot for the in-flight statuses (see ACTIVE_STATUSES).
 */
export function StatusBadge({
  status,
  className,
  ...props
}: StatusBadgeProps) {
  const isActive = ACTIVE_STATUSES.includes(status);

  return (
    <Badge
      variant={STATUS_TO_VARIANT[status] ?? "secondary"}
      className={cn("gap-1.5 capitalize", className)}
      {...props}
    >
      {isActive && (
        <span
          className={cn(
            "w-1.5 h-1.5 rounded-full animate-pulse",
            // paused_hitl renders on the yellow "medium" variant, which needs a
            // dark dot; the blue in-flight variants need a light one.
            status === InvestigationStatus.PAUSED_HITL
              ? "bg-black/70"
              : "bg-white/90"
          )}
        />
      )}
      {status.replace(/_/g, " ")}
    </Badge>
  );
}
