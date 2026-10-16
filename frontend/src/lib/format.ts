import type { Category, Source } from "./types";

export function timeAgo(ts: number | null | undefined): string {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  if (s < 86400 * 30) return `${Math.round(s / 86400)}d ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

export function formatDate(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function duration(start?: number | null, end?: number | null): string {
  if (!start) return "—";
  const secs = (end ?? Date.now() / 1000) - start;
  if (secs < 1) return `${Math.round(secs * 1000)}ms`;
  if (secs < 60) return `${secs.toFixed(1)}s`;
  return `${Math.floor(secs / 60)}m ${Math.round(secs % 60)}s`;
}

export const shortHash = (h?: string | null, n = 12) => (h ? h.slice(0, n) : "—");

export const CATEGORY_LABEL: Record<Category, string> = {
  tool_poisoning: "Tool poisoning",
  command_injection: "Command injection",
  unsafe_deserialization: "Unsafe deserialization",
  hardcoded_secret: "Hardcoded secret",
  excess_access: "Excess access",
  behavior_mismatch: "Behavior mismatch",
  exfiltration: "Exfiltration",
  rug_pull: "Rug pull",
};

export const SOURCE_LABEL: Record<Source, string> = {
  static: "Static",
  description: "Description AI",
  dynamic: "Dynamic",
  pin_diff: "Pin & Diff",
};

/** Short display name for a scan target (folder name or owner/repo). */
export function targetName(target: string): string {
  const clean = target.replace(/\/+$/, "").replace(/\.git$/, "");
  const parts = clean.split("/");
  if (/^https?:|^git@/.test(target)) return parts.slice(-2).join("/");
  return parts[parts.length - 1] || target;
}

export const pct = (x: number | undefined | null, digits = 0) =>
  x == null ? "—" : `${(x * 100).toFixed(digits)}%`;
