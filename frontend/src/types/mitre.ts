/** MITRE ATT&CK Tactic (column in the matrix) */
export interface MitreTactic {
  id: string;
  short_name: string;
  name: string;
  description: string;
  url: string;
  order: number;
}

/** MITRE ATT&CK Technique */
export interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactic_ids: string[];
  tactic_names: string[];
  platforms: string[];
  data_sources: string[];
  detection: string;
  url: string;
  is_subtechnique: boolean;
  parent_id?: string;
  sub_techniques?: MitreTechnique[];
}

/** MITRE ATT&CK Group / Threat Actor */
export interface MitreGroup {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  technique_ids: string[];
  url: string;
}

/** Coverage data: how many times each technique has been tagged */
export interface CoverageData {
  /** tactic_id -> technique_id -> count */
  matrix: Record<string, Record<string, number>>;
  /** Overall coverage score 0-100 */
  coverage_score: number;
  /** Total tagged techniques */
  total_tagged: number;
  /** Total available techniques */
  total_techniques: number;
}

/** A gap in detection coverage */
export interface DetectionGap {
  technique_id: string;
  technique_name: string;
  tactic: string;
  severity: "critical" | "high" | "medium" | "low";
  reason: string;
  recommendation: string;
}

/** Tag linking a technique to an investigation */
export interface TechniqueTag {
  technique_id: string;
  investigation_id: string;
  investigation_title: string;
  confidence: number;
  tagged_at: string;
  tagged_by: string;
}

/** Per-investigation technique usage summary */
export interface InvestigationTechniqueRef {
  investigation_id: string;
  investigation_title: string;
  confidence: number;
  tagged_at: string;
}

/** ATT&CK Navigator layer export format */
export interface NavigatorLayer {
  name: string;
  versions: {
    attack: string;
    navigator: string;
    layer: string;
  };
  domain: string;
  description: string;
  techniques: Array<{
    techniqueID: string;
    tactic: string;
    color: string;
    comment: string;
    score: number;
    enabled: boolean;
  }>;
}
