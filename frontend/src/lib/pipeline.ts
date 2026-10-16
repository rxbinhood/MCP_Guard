// Pipeline step definitions and event folding, shared by the stepper and pages.
import type { ModuleStatus, ScanEvent } from "./types";

export const STEPS = [
  { id: "ingest", label: "Ingest", hint: "Clone, sandbox, tools/list" },
  { id: "static", label: "Static", hint: "Semgrep · Bandit · Gitleaks" },
  { id: "description", label: "Description AI", hint: "Rules · Prompt Guard · LLM" },
  { id: "dynamic", label: "Dynamic", hint: "strace · canaries · proxy" },
  { id: "report", label: "Report", hint: "Merge, verdict, risk" },
] as const;

export type StepState = { status: ModuleStatus["status"]; detail?: string | null; started?: number; elapsed?: number };

/** Fold the event stream (or a finished result's module list) into per-step state. */
export function stepStates(events: ScanEvent[], modules?: ModuleStatus[]): Record<string, StepState> {
  const out: Record<string, StepState> = Object.fromEntries(STEPS.map((s) => [s.id, { status: "pending" as const }]));
  if (modules?.length && !events.length) {
    for (const m of modules)
      out[m.name] = {
        status: m.status, detail: m.detail,
        elapsed: m.started_at && m.finished_at ? m.finished_at - m.started_at : undefined,
      };
    return out;
  }
  for (const e of events) {
    if (e.type !== "module" || !e.module) continue;
    const prev = out[e.module] ?? { status: "pending" };
    out[e.module] = {
      status: e.status as StepState["status"],
      detail: e.detail ?? prev.detail,
      started: e.status === "running" ? e.ts : prev.started,
      elapsed: e.elapsed ?? prev.elapsed,
    };
  }
  return out;
}
