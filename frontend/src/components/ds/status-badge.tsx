import { Badge } from "@/components/ds/badge";
import { cn } from "@/lib/utils";
import { InvestigationStatus } from "@/types/config";

const STATUS_TO_VARIANT: Record<
  InvestigationStatus,
  "default" | "secondary" | "destructive" | "outline" | "low" | "medium" | "info"
> = {
  [InvestigationStatus.PENDING]: "secondary",
  [InvestigationStatus.RUNNING]: "low",         // blue = active
  [InvestigationStatus.AWAITING_HITL]: "medium", // yellow = needs human
  [InvestigationStatus.PAUSED]: "outline",
  [InvestigationStatus.COMPLETED]: "info",
  [InvestigationStatus.FAILED]: "destructive",
  [InvestigationStatus.STOPPED]: "outline",
};

interface StatusBadgeProps {
  status: InvestigationStatus;
  className?: string;
  "data-testid"?: string;
}

/**
 * StatusBadge — maps an InvestigationStatus to a Badge variant and
 * adds a pulsing dot for "active" statuses (RUNNING, AWAITING_HITL).
 */
export function StatusBadge({
  status,
  className,
  ...props
}: StatusBadgeProps) {
  const isActive =
    status === InvestigationStatus.RUNNING ||
    status === InvestigationStatus.AWAITING_HITL;

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
            status === InvestigationStatus.RUNNING && "bg-white/90",
            status === InvestigationStatus.AWAITING_HITL && "bg-black/70"
          )}
        />
      )}
      {status.replace("_", " ")}
    </Badge>
  );
}
