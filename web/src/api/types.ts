// Tipos de /api/v1 (fuente: api/views/serializers.py y docs/api/openapi.yaml).

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type ScanStatus = "queued" | "running" | "done" | "failed" | "canceled";
export type Triage = "untriaged" | "confirmed" | "false_positive" | "accepted" | "wont_fix";
export type Change = "new" | "persisting" | "reopened";
export type Lifecycle = "open" | "fixed" | "reopened";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const TRIAGES: Triage[] = ["untriaged", "confirmed", "false_positive", "accepted", "wont_fix"];
export const CHANGES: Change[] = ["new", "persisting", "reopened"];

export interface Me {
  id: string;
  email: string;
  name: string;
  csrf_token: string;
}

export interface PublicConfig {
  version: string;
  auth: { oidc: boolean; google: boolean; provider: string; dev_login: boolean };
  limits: {
    max_upload_mb: number;
    max_snippet_kb: number;
    max_zip_entries: number;
    max_total_uncompressed_mb: number;
    max_compression_ratio: number;
    github_max_mb: number;
    scan_timeout_s: number;
    scans_per_hour: number;
    retention_days: number;
  };
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export type SeverityCounts = Partial<Record<Severity, number>>;

export interface ScanSummaryData {
  by_severity?: SeverityCounts;
  new?: number;
  fixed?: number;
  persisting?: number;
  reopened?: number;
  suppressed?: number;
  total?: number;
}

export interface ScanBrief {
  id: string;
  status: ScanStatus;
  finished_at: string | null;
  summary: ScanSummaryData;
}

export interface Project {
  id: string;
  name: string;
  created_at: string;
  last_scan: ScanBrief | null;
  open_by_severity?: SeverityCounts;
}

export interface RuleError {
  rule_id?: string;
  path?: string;
  error?: string;
  message?: string;
}

export interface Scan {
  id: string;
  project_id: string;
  status: ScanStatus;
  source: "snippet" | "zip" | "github";
  source_ref: string | null;
  category: string | null;
  commit_sha: string | null;
  progress: { files_done: number | null; files_total: number | null };
  queued_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  summary: ScanSummaryData;
  rule_errors: RuleError[];
  error_code: string | null;
  cancel_requested: boolean;
  files_scanned: number | null;
  loc_total: number | null;
  engine_version: string | null;
  baseline_scan_id: string | null;
  rules_requested: string[] | null;
}

export interface TraceStep {
  line: number;
  description?: string;
  desc?: string;
}

export interface Finding {
  occurrence_id: string;
  issue_id: string;
  rule_id: string;
  severity: Severity;
  confidence: Confidence;
  path: string;
  start_line: number;
  end_line: number | null;
  start_col: number | null;
  message: string;
  snippet: string | null;
  trace: TraceStep[];
  variant: string | null;
  change: Change | null;
  triage: Triage;
  lifecycle: Lifecycle;
  suppressed: boolean;
  suppression_reason: string | null;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  owasp: string[];
  kind: string;
  languages: string[];
  engine: string;
  security_severity: number | null;
  message: string;
  explanation_es: string;
  remediation_es: string;
  example_bad: string;
  example_good: string;
  references: string[];
}

export interface Issue {
  id: string;
  project_id: string;
  rule_id: string;
  category: string | null;
  lifecycle: Lifecycle;
  triage: Triage;
  triage_justification: string | null;
  severity: Severity;
  path: string;
  line: number;
  message: string;
  first_seen_at: string;
  fixed_at: string | null;
  first_seen_scan_id: string | null;
  last_seen_scan_id: string | null;
  reopened_count: number;
  fingerprint: string;
  last_occurrence?: Finding;
  rule?: Rule;
}

export interface IssueEvent {
  kind: string;
  from: string | null;
  to: string | null;
  comment: string | null;
  user: { id: string; name: string } | null;
  scan_id: string | null;
  created_at: string;
}

export interface ScanDiff {
  base_scan_id: string | null;
  new: Finding[];
  fixed: Finding[];
  reopened: Finding[];
  persisting_count: number;
}

export interface Metrics {
  open_by_severity: ({ scan_id: string; date: string | null } & Record<Severity, number>)[];
  new_vs_fixed: { scan_id: string; date: string | null; new: number; fixed: number }[];
  mttr_days: Partial<Record<Severity, { median: number; mean: number; count: number }>>;
  density_per_kloc: number | null;
  open_issues: number;
  accepted_issues: number;
}
