import { AnimatePresence, motion } from "framer-motion";
import { Check, Circle, Loader2, MinusCircle, Terminal, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { STEPS, type StepState } from "@/lib/pipeline";
import type { ScanEvent } from "@/lib/types";

function useNow(active: boolean) {
  const [now, setNow] = useState(Date.now() / 1000);
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now() / 1000), 200);
    return () => clearInterval(t);
  }, [active]);
  return now;
}

function StepIcon({ status }: { status: StepState["status"] }) {
  const base = "grid size-9 place-items-center rounded-full ring-2 transition-colors";
  switch (status) {
    case "running":
      return <span className={cn(base, "bg-teal/15 text-teal ring-teal/50")}><Loader2 className="size-4 animate-spin" /></span>;
    case "done":
      return <span className={cn(base, "bg-success/15 text-success ring-success/50")}><Check className="size-4" /></span>;
    case "failed":
      return <span className={cn(base, "bg-danger/15 text-danger ring-danger/50")}><X className="size-4" /></span>;
    case "skipped":
      return <span className={cn(base, "bg-muted text-muted-foreground ring-border")}><MinusCircle className="size-4" /></span>;
    default:
      return <span className={cn(base, "bg-muted text-muted-foreground ring-border")}><Circle className="size-3" /></span>;
  }
}

export function PipelineStepper({ states }: { states: Record<string, StepState> }) {
  const running = Object.values(states).some((s) => s.status === "running");
  const now = useNow(running);
  return (
    <ol className="grid gap-3 sm:grid-cols-5" aria-label="Scan pipeline">
      {STEPS.map((step, i) => {
        const s = states[step.id];
        const elapsed = s.status === "running" && s.started ? now - s.started : s.elapsed;
        return (
          <li key={step.id} className="relative flex flex-row items-center gap-3 sm:flex-col sm:items-start" aria-current={s.status === "running" ? "step" : undefined}>
            {i < STEPS.length - 1 && (
              <span
                aria-hidden
                className={cn(
                  "absolute left-[2.6rem] -right-3 top-[1.1rem] hidden h-0.5 rounded sm:block",
                  s.status === "done" ? "bg-success/50" : s.status === "skipped" ? "bg-border" : "bg-border",
                )}
              />
            )}
            <StepIcon status={s.status} />
            <div className="min-w-0">
              <p className="text-sm font-medium">{step.label}</p>
              <p className="truncate text-xs text-muted-foreground" title={s.detail ?? step.hint}>
                {s.status === "pending" ? step.hint : s.detail ?? s.status}
              </p>
              <p className="mt-0.5 font-mono text-[11px] tabular-nums text-muted-foreground">
                {elapsed != null ? `${elapsed.toFixed(1)}s` : s.status === "skipped" ? "skipped" : "—"}
              </p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

const LEVEL_TONE: Record<string, string> = { info: "text-slate-300", warn: "text-amber-300", error: "text-red-300" };

export function LogConsole({ events, live, className }: { events: ScanEvent[]; live?: boolean; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);
  const lines = useMemo(() => events.filter((e) => e.type === "log" || e.type === "module" || e.type === "scan"), [events]);
  const t0 = events[0]?.ts ?? 0;

  useEffect(() => {
    if (follow && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines.length, follow]);

  return (
    <div className={cn("overflow-hidden rounded-xl border border-slate-800 bg-[#070c17] shadow-inner", className)}>
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2">
        <span className="flex items-center gap-2 text-xs font-medium text-slate-300">
          <Terminal className="size-3.5" /> Scan log
        </span>
        <span className="flex items-center gap-2 text-[11px] text-slate-400">
          {live && (
            <span className="flex items-center gap-1.5">
              <span className="size-1.5 animate-pulse rounded-full bg-teal" /> streaming
            </span>
          )}
          <span className="tabular-nums">{lines.length} lines</span>
        </span>
      </div>
      <div
        ref={ref}
        onScroll={(e) => {
          const el = e.currentTarget;
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
        }}
        className="h-72 overflow-auto px-4 py-3 font-mono text-[12px] leading-relaxed scrollbar-thin"
        role="log"
        aria-live="polite"
      >
        {!lines.length && <p className="text-slate-500">Waiting for events…</p>}
        <AnimatePresence initial={false}>
          {lines.map((e, i) => (
            <motion.div key={e.seq ?? i} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.12 }} className="flex gap-3">
              <span className="w-12 shrink-0 text-right tabular-nums text-slate-600">+{Math.max(0, e.ts - t0).toFixed(1)}s</span>
              {e.type === "log" ? (
                <>
                  <span className="w-20 shrink-0 truncate text-indigo-300">{e.module}</span>
                  <span className={cn("break-all", LEVEL_TONE[e.level ?? "info"])}>{e.message}</span>
                </>
              ) : e.type === "module" ? (
                <span className={cn("font-semibold", e.status === "failed" ? "text-red-300" : e.status === "done" ? "text-emerald-300" : e.status === "skipped" ? "text-slate-500" : "text-teal-300")}>
                  {e.status === "running" ? "▶" : e.status === "done" ? "✔" : e.status === "failed" ? "✖" : "–"} {e.module} {e.status}
                  {e.detail ? <span className="font-normal text-slate-400"> · {e.detail}</span> : null}
                </span>
              ) : (
                <span className="font-semibold text-slate-200">
                  ● scan {e.status}
                  {e.verdict ? ` · verdict ${e.verdict} · risk ${e.risk_score}/100` : ""}
                  {e.error ? ` · ${e.error}` : ""}
                </span>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
