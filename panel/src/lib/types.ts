export type Severity = "clean" | "info" | "low" | "medium" | "high" | "critical";
export type MemberRole = "owner" | "admin" | "checker";
export type SessionStatus = "pending" | "consumed" | "expired" | "revoked" | "completed";
export type ReportStatus = "running" | "complete" | "aborted" | "error";

export const SEVERITY_ORDER: Severity[] = ["clean", "info", "low", "medium", "high", "critical"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  clean: "Clean",
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

/** tailwind text/border classes per severity (see tailwind.config.js `sev`) */
export const SEVERITY_CLASS: Record<Severity, string> = {
  clean: "text-sev-clean border-sev-clean",
  info: "text-sev-info border-sev-info",
  low: "text-sev-low border-sev-low",
  medium: "text-sev-medium border-sev-medium",
  high: "text-sev-high border-sev-high",
  critical: "text-white bg-sev-critical border-sev-critical",
};

export function worstSeverity(list: Severity[]): Severity {
  return list.reduce<Severity>(
    (acc, s) => (SEVERITY_ORDER.indexOf(s) > SEVERITY_ORDER.indexOf(acc) ? s : acc),
    "clean",
  );
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  retention_days: number;
  plan: string;
  created_at: string;
}

export interface SessionRow {
  id: string;
  tenant_id: string;
  case_label: string;
  suspect_label: string | null;
  key_prefix: string;
  status: SessionStatus;
  created_by: string;
  expires_at: string;
  consumed_at: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  tenant_id: string;
  session_id: string;
  status: ReportStatus;
  verdict_severity: Severity;
  findings_count: Partial<Record<Severity, number>>;
  consent: Record<string, unknown> | null;
  environment: Record<string, unknown> | null;
  signature_db_version: string | null;
  client_version: string | null;
  started_at: string;
  completed_at: string | null;
}

export interface Finding {
  id: string;
  report_id: string;
  module: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  occurred_at: string | null;
  sort_key: number;
}

export interface ReportEvent {
  id: number;
  report_id: string;
  kind: string;
  module: string | null;
  message: string;
  pct: number | null;
  created_at: string;
}
