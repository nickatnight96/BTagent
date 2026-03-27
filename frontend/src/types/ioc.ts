import type { TLP } from "./config";

/** IOC type identifiers matching backend enum */
export type IOCType =
  | "ip"
  | "domain"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "url"
  | "email"
  | "cve"
  | "file_path"
  | "other";

export type EnrichmentStatus = "pending" | "enriching" | "enriched" | "failed";

/** Per-source enrichment result */
export interface EnrichmentResult {
  source: string;
  status: EnrichmentStatus;
  timestamp: string;
  data: Record<string, unknown>;
  error?: string;
}

/** VirusTotal specific enrichment */
export interface VTEnrichment {
  positives: number;
  total: number;
  reputation: number;
  last_analysis_date: string;
  categories: Record<string, string>;
}

/** Shodan specific enrichment */
export interface ShodanEnrichment {
  ip: string;
  ports: number[];
  vulns: string[];
  os: string | null;
  isp: string;
  country: string;
  city: string;
  last_update: string;
}

/** GreyNoise specific enrichment */
export interface GreyNoiseEnrichment {
  classification: "benign" | "malicious" | "unknown";
  noise: boolean;
  riot: boolean;
  name: string;
  last_seen: string;
}

/** AbuseIPDB specific enrichment */
export interface AbuseIPDBEnrichment {
  abuse_confidence_score: number;
  total_reports: number;
  country_code: string;
  isp: string;
  domain: string;
  usage_type: string;
  last_reported_at: string;
}

/** MISP specific enrichment */
export interface MISPEnrichment {
  event_count: number;
  events: Array<{
    id: string;
    info: string;
    date: string;
    threat_level: number;
  }>;
  tags: string[];
}

/** Full enrichment data container */
export interface EnrichmentData {
  virus_total?: VTEnrichment;
  shodan?: ShodanEnrichment;
  grey_noise?: GreyNoiseEnrichment;
  abuse_ipdb?: AbuseIPDBEnrichment;
  misp?: MISPEnrichment;
  raw_results: EnrichmentResult[];
}

/** MITRE technique reference on an IOC */
export interface MitreTag {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

/** Extended IOC with enrichment and MITRE data */
export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  source: string;
  confidence: number;
  tags: string[];
  first_seen: string;
  last_seen?: string;
  context?: string;
  investigation_id?: string;
  investigation_title?: string;
  enrichment_status: EnrichmentStatus;
  enrichment_data?: EnrichmentData;
  mitre_tags: MitreTag[];
  tlp: TLP;
  related_ioc_ids: string[];
}

/** IOC filter parameters */
export interface IOCFilter {
  type?: IOCType;
  confidence_min?: number;
  enriched?: boolean;
  investigation_id?: string;
  search?: string;
  tlp?: TLP;
}

/** Sort configuration */
export type IOCSortField = "type" | "value" | "confidence" | "source" | "first_seen" | "enrichment_status";
export type SortDirection = "asc" | "desc";

export interface IOCSortConfig {
  field: IOCSortField;
  direction: SortDirection;
}

/** Import result from CSV/STIX ingest */
export interface ImportResult {
  total_parsed: number;
  imported: number;
  skipped: number;
  errors: Array<{
    line: number;
    value: string;
    reason: string;
  }>;
  iocs: IOC[];
}

/** Export options */
export interface ExportOptions {
  format: "stix_2.1" | "csv" | "json";
  investigation_id?: string;
  type?: IOCType;
  confidence_min?: number;
  tlp_max?: TLP;
}

/** Preview row before import */
export interface ImportPreviewRow {
  type: IOCType;
  value: string;
  source: string;
  confidence: number;
  tags: string[];
  valid: boolean;
  error?: string;
}
