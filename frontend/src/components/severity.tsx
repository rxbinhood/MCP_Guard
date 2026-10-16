// Severity, verdict and status badges. Every badge pairs color with an icon and a text
// label so meaning never depends on color alone (WCAG 1.4.1).
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  CircleDot,
  Info,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { Severity, Verdict } from "@/lib/types";

export const SEVERITY_META: Record<Severity, { icon: LucideIcon; text: string; bg: string; ring: string; hex: string }> = {
  CRITICAL: { icon: AlertOctagon, text: "text-sev-critical-fg", bg: "bg-sev-critical/12", ring: "ring-sev-critical/30", hex: "var(--sev-critical)" },
  HIGH: { icon: ShieldAlert, text: "text-sev-high-fg", bg: "bg-sev-high/12", ring: "ring-sev-high/30", hex: "var(--sev-high)" },
  MEDIUM: { icon: AlertTriangle, text: "text-sev-medium-fg", bg: "bg-sev-medium/12", ring: "ring-sev-medium/30", hex: "var(--sev-medium)" },
  LOW: { icon: CircleDot, text: "text-sev-low-fg", bg: "bg-sev-low/12", ring: "ring-sev-low/30", hex: "var(--sev-low)" },
  INFO: { icon: Info, text: "text-sev-info-fg", bg: "bg-sev-info/12", ring: "ring-sev-info/30", hex: "var(--sev-info)" },
};

export function SeverityBadge({ severity, className, compact }: { severity: Severity; className?: string; compact?: boolean }) {
  const m = SEVERITY_META[severity];
  const Icon = m.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold tracking-wide ring-1 ring-inset",
        m.text, m.bg, m.ring, className,
      )}
    >
      <Icon className="size-3.5" aria-hidden />
      {compact ? { CRITICAL: "CRIT", HIGH: "HIGH", MEDIUM: "MED", LOW: "LOW", INFO: "INFO" }[severity] : severity}
    </span>
  );
}

export const VERDICT_META: Record<Verdict, { icon: LucideIcon; label: string; text: string; bg: string; ring: string; hex: string; blurb: string }> = {
  PASS: { icon: ShieldCheck, label: "PASS", text: "text-success", bg: "bg-success/12", ring: "ring-success/30", hex: "var(--success)",
    blurb: "No medium or higher findings. Safe to connect, and pin it to detect future changes." },
  WARN: { icon: AlertTriangle, label: "WARN", text: "text-warning", bg: "bg-warning/12", ring: "ring-warning/30", hex: "var(--warning)",
    blurb: "Medium-severity issues found. Review before connecting this server to an agent." },
  FAIL: { icon: ShieldX, label: "FAIL", text: "text-danger", bg: "bg-danger/12", ring: "ring-danger/30", hex: "var(--danger)",
    blurb: "Critical or high-severity issues found. Do not connect this server to an agent." },
};

export function VerdictBadge({ verdict, className }: { verdict: Verdict | null | undefined; className?: string }) {
  if (!verdict) return <span className="text-xs text-muted-foreground">—</span>;
  const m = VERDICT_META[verdict];
  const Icon = m.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset", m.text, m.bg, m.ring, className)}>
      <Icon className="size-3.5" aria-hidden />
      {m.label}
    </span>
  );
}

export function HealthPill({ ok, label, className }: { ok: boolean; label?: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset",
        ok ? "bg-success/10 text-success ring-success/25" : "bg-danger/10 text-danger ring-danger/25",
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", ok ? "bg-success" : "bg-danger")} aria-hidden />
      {label ?? (ok ? "Online" : "Offline")}
    </span>
  );
}

export function StatusDot({ status }: { status: string }) {
  const map: Record<string, string> = {
    done: "bg-success", running: "bg-teal animate-pulse", queued: "bg-sev-info", failed: "bg-danger",
  };
  return <span className={cn("inline-block size-2 rounded-full", map[status] ?? "bg-sev-info")} aria-hidden />;
}

export function CheckLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 text-success">
      <CheckCircle2 className="size-3.5" /> {children}
    </span>
  );
}
