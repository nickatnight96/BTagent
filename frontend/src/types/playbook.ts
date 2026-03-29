/** TypeScript types matching shared Pydantic playbook models. */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export enum StepType {
  ACTION = "action",
  DECISION = "decision",
  HITL_GATE = "hitl_gate",
  PARALLEL_FORK = "parallel_fork",
  JOIN = "join",
  END = "end",
}

export enum TriggerType {
  ALERT_SEVERITY = "alert_severity",
  IOC_TYPE = "ioc_type",
  MANUAL = "manual",
  WEBHOOK = "webhook",
  SCHEDULE = "schedule",
}

export enum OnFailure {
  SKIP = "skip",
  ABORT = "abort",
  RETRY = "retry",
}

export enum PlaybookStatus {
  PENDING = "pending",
  RUNNING = "running",
  PAUSED_HITL = "paused_hitl",
  COMPLETED = "completed",
  FAILED = "failed",
  CANCELLED = "cancelled",
}

export enum StepExecutionStatus {
  PENDING = "pending",
  RUNNING = "running",
  COMPLETED = "completed",
  FAILED = "failed",
  SKIPPED = "skipped",
  WAITING_HITL = "waiting_hitl",
}

// ---------------------------------------------------------------------------
// Trigger
// ---------------------------------------------------------------------------

export interface TriggerCondition {
  type: TriggerType;
  parameters: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

export interface PlaybookStep {
  id: string;
  type: StepType;
  name: string;
  description: string;
  config: Record<string, unknown>;
  next_step: string | null;
  on_failure: OnFailure;
}

export interface ActionStep extends PlaybookStep {
  type: StepType.ACTION;
  tool_name: string;
  arguments: Record<string, unknown>;
  timeout_seconds: number;
}

export interface DecisionStep extends PlaybookStep {
  type: StepType.DECISION;
  condition: string;
  true_branch: string;
  false_branch: string;
}

export interface HITLGateStep extends PlaybookStep {
  type: StepType.HITL_GATE;
  prompt: string;
  timeout_seconds: number;
  required_role: string;
}

export interface ParallelForkStep extends PlaybookStep {
  type: StepType.PARALLEL_FORK;
  branches: string[][];
}

// ---------------------------------------------------------------------------
// Playbook definition
// ---------------------------------------------------------------------------

export interface PlaybookDefinition {
  name: string;
  version: string;
  description: string;
  trigger: TriggerCondition;
  steps: PlaybookStep[];
}

// ---------------------------------------------------------------------------
// Playbook (persisted entity with metadata)
// ---------------------------------------------------------------------------

export interface Playbook {
  id: string;
  name: string;
  version?: string;
  description: string;
  trigger?: TriggerCondition;
  steps?: PlaybookStep[];
  is_active?: boolean;
  created_at?: string;
  updated_at?: string;
  created_by?: string;
  execution_count?: number;
  last_executed_at?: string | null;
  tags?: string[];
}

export interface CreatePlaybookRequest {
  name: string;
  description: string;
  version?: string;
  trigger: TriggerCondition;
  steps: PlaybookStep[];
  tags?: string[];
}

export interface UpdatePlaybookRequest {
  name?: string;
  description?: string;
  version?: string;
  trigger?: TriggerCondition;
  steps?: PlaybookStep[];
  is_active?: boolean;
  tags?: string[];
}

// ---------------------------------------------------------------------------
// Execution tracking
// ---------------------------------------------------------------------------

export interface StepResult {
  step_id: string;
  status: StepExecutionStatus;
  started_at: string | null;
  completed_at: string | null;
  output?: Record<string, unknown>;
  error?: string | null;
}

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  investigation_id: string | null;
  status: PlaybookStatus;
  started_at: string | null;
  completed_at: string | null;
  step_results?: StepResult[];
  error?: string | null;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  step_count: number;
}

// ---------------------------------------------------------------------------
// React Flow node data
// ---------------------------------------------------------------------------

export interface TriggerNodeData {
  label: string;
  triggerType: TriggerType;
  parameters: Record<string, unknown>;
}

export interface ActionNodeData {
  label: string;
  toolName: string;
  arguments: Record<string, unknown>;
  timeoutSeconds: number;
  onFailure: OnFailure;
}

export interface DecisionNodeData {
  label: string;
  condition: string;
}

export interface HITLGateNodeData {
  label: string;
  prompt: string;
  timeoutSeconds: number;
  requiredRole: string;
}

export interface ParallelForkNodeData {
  label: string;
  branchCount: number;
  branchLabels: string[];
}

export interface EndNodeData {
  label: string;
}

export type PlaybookNodeData =
  | TriggerNodeData
  | ActionNodeData
  | DecisionNodeData
  | HITLGateNodeData
  | ParallelForkNodeData
  | EndNodeData;
