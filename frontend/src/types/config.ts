export enum TLP {
  RED = "RED",
  AMBER = "AMBER",
  AMBER_STRICT = "AMBER+STRICT",
  GREEN = "GREEN",
  CLEAR = "CLEAR",
}

export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info",
}

export enum InvestigationStatus {
  PENDING = "pending",
  RUNNING = "running",
  PAUSED = "paused",
  AWAITING_HITL = "awaiting_hitl",
  COMPLETED = "completed",
  FAILED = "failed",
  STOPPED = "stopped",
}

export enum UserRole {
  ADMIN = "admin",
  ANALYST = "analyst",
  VIEWER = "viewer",
}

export interface User {
  id: string;
  username: string;
  role: UserRole;
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  [Severity.CRITICAL]: "bg-red-500/20 text-red-400 border-red-500/30",
  [Severity.HIGH]: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  [Severity.MEDIUM]: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  [Severity.LOW]: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  [Severity.INFO]: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export const STATUS_COLORS: Record<InvestigationStatus, string> = {
  [InvestigationStatus.PENDING]: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  [InvestigationStatus.RUNNING]: "bg-green-500/20 text-green-400 border-green-500/30",
  [InvestigationStatus.PAUSED]: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  [InvestigationStatus.AWAITING_HITL]: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  [InvestigationStatus.COMPLETED]: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  [InvestigationStatus.FAILED]: "bg-red-500/20 text-red-400 border-red-500/30",
  [InvestigationStatus.STOPPED]: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};
