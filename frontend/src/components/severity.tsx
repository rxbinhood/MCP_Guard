// Severity, verdict and status badges. Every badge pairs color with an icon and a text
// label so meaning never depends on color alone (WCAG 1.4.1).
import { CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { SEVERITY_META, VERDICT_META } from "@/lib/severity";
import type { Severity, Verdict } from "@/lib/types";



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
