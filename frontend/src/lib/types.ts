// TypeScript mirrors of the MCPGuard backend models (mcpguard/findings.py, pin_diff/*).

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export type Category =
  | "tool_poisoning"
  | "command_injection"
  | "unsafe_deserialization"
  | "hardcoded_secret"
  | "excess_access"
  | "behavior_mismatch"
  | "exfiltration"
  | "rug_pull";

export type Source = "static" | "description" | "dynamic" | "pin_diff";
export type Verdict = "PASS" | "WARN" | "FAIL";

export interface Finding {
  id: string;
  severity: Severity;
  category: Category;
  tool: string | null;
  title: string;
  evidence: string;
  fix: string;
  source: Source;
  confidence: number;
  owasp_llm_ref?: string | null;
  rule_id?: string | null;
  file?: string | null;
  line?: number | null;
  highlights: string[];
  detectors: string[];
  why?: string | null;
  extra: Record<string, unknown>;
}

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string; title?: string; default?: unknown; anyOf?: { type?: string }[] }>;
    required?: string[];
  };
}

export interface Manifest {
  server_name: string;
  server_version?: string | null;
  tools: ToolDef[];
  method: "docker" | "host" | "static";
}

export interface ToolSignal {
  layer: "rules" | "prompt_guard" | "llm";
  rule?: string;
  title?: string;
  field?: string;
  match?: string;
  weight?: number;
  decoded?: string | null;
  score?: number;
  malicious?: boolean;
  confidence?: number;
  reason?: string;
  suspicious_text?: string;
}

export interface ToolVerdict {
  tool: string;
  verdict: "clean" | "suspicious" | "malicious";
  score: number;
  claimed_behavior?: string | null;
  claimed_capabilities: string[];
  highlights: { field: string; text: string }[];
  signals: ToolSignal[];
  layers_used: string[];
}

export interface ModuleStatus {
  name: string;
  status: "pending" | "running" | "done" | "skipped" | "failed";
  started_at?: number | null;
  finished_at?: number | null;
  detail?: string | null;
}

export interface EngineInfo {
  status: string;
  detail?: string;
  errors?: string[];
}

export interface ScanResult {
  id: string;
  target: string;
  server_name: string;
  language?: string | null;
  started_at: number;
  finished_at?: number | null;
  verdict: Verdict;
  risk_score: number;
  manifest?: Manifest | null;
  findings: Finding[];
  tool_verdicts: ToolVerdict[];
  modules: ModuleStatus[];
  engines: Record<string, EngineInfo>;
  options: Record<string, unknown>;
  error?: string | null;
}

export type Counts = Record<Severity, number>;

export interface ScanSummary {
  id: string;
  target: string;
  server_name: string | null;
  status: "queued" | "running" | "done" | "failed";
  verdict: Verdict | null;
  risk_score: number | null;
  counts: Counts | null;
  options: Record<string, unknown> | null;
  started_at: number;
  finished_at: number | null;
}

export interface ScanDetail extends ScanSummary {
  result: ScanResult | null;
}

export interface ScanEvent {
  seq?: number;
  type: "scan" | "module" | "log";
  ts: number;
  module?: string;
  status?: string;
  detail?: string | null;
  elapsed?: number;
  message?: string;
  level?: string;
  verdict?: Verdict;
  risk_score?: number;
  error?: string;
}

export interface Engine {
  id: string;
  label: string;
  kind: "ai" | "sandbox" | "static" | "storage";
  model?: string;
  ok: boolean;
  status: "online" | "offline";
  detail: string;
}

export interface Health {
  status: string;
  version: string;
  ai_online: boolean;
  engines: Engine[];
}

export interface Stats {
  servers_scanned: number;
  total_scans: number;
  total_findings: number;
  critical_high: number;
  pinned_servers: number;
  changed_pins: number;
  severity: Counts;
  by_source: Record<string, Partial<Counts>>;
  by_category: Record<string, number>;
  verdicts: Record<string, number>;
  timeline: ({ date: string } & Record<string, number | string>)[];
}

export interface PinSummary {
  server_key: string;
  server_name: string;
  server_version?: string | null;
  target: string;
  manifest_hash: string;
  tool_hashes: Record<string, string>;
  pinned_at: number;
  last_verified_at: number | null;
  last_status: "pinned" | "unchanged" | "changed" | "error" | null;
  tools: number;
  method?: string;
}

export interface FieldChange {
  path: string;
  kind: "changed" | "added" | "removed" | "type_changed";
  old: unknown;
  new: unknown;
}

export interface ToolChange {
  tool: string;
  status: "added" | "removed" | "changed";
  old_hash?: string | null;
  new_hash?: string | null;
  fields: FieldChange[];
  old_text: string;
  new_text: string;
}

export interface ManifestDiff {
  status: "unchanged" | "changed";
  old_hash: string;
  new_hash: string;
  added: string[];
  removed: string[];
  changed: string[];
  tools: ToolChange[];
  summary: string;
}

export interface VerifyResult {
  server_key: string;
  server_name: string;
  status: "unchanged" | "changed" | "error";
  diff: ManifestDiff | null;
  findings: Finding[];
  rug_pull: boolean;
  error?: string | null;
  checked_at: number;
  engines: Record<string, EngineInfo>;
}

export interface PinCheck {
  id: number;
  server_key: string;
  ts: number;
  status: string;
  manifest_hash: string | null;
  diff: ManifestDiff | null;
  findings: Finding[];
}

export interface PinDetail extends PinSummary {
  manifest: Manifest;
  checks: PinCheck[];
}

export interface EvalMode {
  n: number;
  tp: number;
  fn: number;
  fp: number;
  tn: number;
  detection_rate: number;
  false_positive_rate: number;
  precision: number;
  layers: string[];
}

export interface EvalServer {
  server: string;
  expected: Verdict;
  planted: string;
  verdict: Verdict;
  risk_score: number;
  passed: boolean;
  findings: number;
  caught_by: Source[];
  top_finding: string | null;
  scan_id: string;
}

export interface EvalResults {
  generated_at: number;
  descriptions: {
    available: boolean;
    reason?: string;
    threshold?: number;
    modes?: Record<string, EvalMode>;
    by_kind?: Record<string, { total: number; flagged: number }>;
  };
  servers?: EvalServer[];
}

export interface EvalResponse {
  state: { running: boolean; error: string | null };
  results: EvalResults | null;
  expected: { server: string; expected: Verdict; planted: string }[];
}

export interface Settings {
  llm_base_url: string;
  llm_model: string;
  llm_api_key_set: boolean;
  promptguard_url: string;
  promptguard_model: string;
  sandbox: string;
  home: string;
}

export interface About {
  version: string;
  license: string;
  models: {
    role: string;
    name: string;
    provider: string;
    parameters: string;
    endpoint?: string;
    model_id?: string;
    license_url?: string | null;
    card_url?: string;
  }[];
}
