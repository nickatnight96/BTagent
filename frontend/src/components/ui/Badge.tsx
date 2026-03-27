import type { HTMLAttributes } from "react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { Severity, InvestigationStatus, SEVERITY_COLORS, STATUS_COLORS } from "@/types/config";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "outline";
}

function Badge({ variant = "default", className, children, ...props }: BadgeProps) {
  return (
    <span
      className={twMerge(
        clsx(
          "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border",
          variant === "default" && "bg-slate-700/50 text-slate-300 border-slate-600/50",
          variant === "outline" && "bg-transparent border-slate-600 text-slate-400",
          className,
        ),
      )}
      {...props}
    >
      {children}
    </span>
  );
}

interface SeverityBadgeProps extends Omit<HTMLAttributes<HTMLSpanElement>, "children"> {
  severity: Severity;
}

function SeverityBadge({ severity, className, ...props }: SeverityBadgeProps) {
  return (
    <span
      className={twMerge(
        clsx(
          "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide border",
          SEVERITY_COLORS[severity],
          className,
        ),
      )}
      {...props}
    >
      {severity === Severity.CRITICAL && (
        <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse-slow" />
      )}
      {severity}
    </span>
  );
}

interface StatusBadgeProps extends Omit<HTMLAttributes<HTMLSpanElement>, "children"> {
  status: InvestigationStatus;
}

function StatusBadge({ status, className, ...props }: StatusBadgeProps) {
  const isActive =
    status === InvestigationStatus.RUNNING ||
    status === InvestigationStatus.AWAITING_HITL;

  return (
    <span
      className={twMerge(
        clsx(
          "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium capitalize border",
          STATUS_COLORS[status],
          className,
        ),
      )}
      {...props}
    >
      {isActive && (
        <span
          className={clsx(
            "w-1.5 h-1.5 rounded-full",
            status === InvestigationStatus.RUNNING && "bg-green-400 animate-pulse",
            status === InvestigationStatus.AWAITING_HITL && "bg-purple-400 animate-pulse",
          )}
        />
      )}
      {status.replace("_", " ")}
    </span>
  );
}

export { Badge, SeverityBadge, StatusBadge };
export type { BadgeProps, SeverityBadgeProps, StatusBadgeProps };
