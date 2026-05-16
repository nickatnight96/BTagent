import { Badge } from "@/components/ds/badge";
import { cn } from "@/lib/utils";
import { Severity } from "@/types/config";

const SEVERITY_TO_VARIANT: Record<
  Severity,
  "critical" | "high" | "medium" | "low" | "info"
> = {
  [Severity.CRITICAL]: "critical",
  [Severity.HIGH]: "high",
  [Severity.MEDIUM]: "medium",
  [Severity.LOW]: "low",
  [Severity.INFO]: "info",
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
  "data-testid"?: string;
}

/**
 * SeverityBadge — maps a Severity enum to the matching severity-*
 * Badge variant (which reads from the severity-{critical,high,...}
 * CSS tokens). Critical severities pulse to draw the eye.
 */
export function SeverityBadge({
  severity,
  className,
  ...props
}: SeverityBadgeProps) {
  return (
    <Badge
      variant={SEVERITY_TO_VARIANT[severity]}
      className={cn("gap-1 uppercase tracking-wide", className)}
      {...props}
    >
      {severity === Severity.CRITICAL && (
        <span className="w-1.5 h-1.5 rounded-full bg-white/80 animate-pulse-slow" />
      )}
      {severity}
    </Badge>
  );
}
