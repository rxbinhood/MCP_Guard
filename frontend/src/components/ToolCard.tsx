import { ChevronDown, Cpu, Globe, HardDrive, ShieldAlert, ShieldCheck, ShieldQuestion, Sparkles, Terminal } from "lucide-react";
import { useState } from "react";
import { HighlightedText } from "@/components/HighlightedText";
import { cn } from "@/lib/utils";
import type { ToolDef, ToolSignal, ToolVerdict } from "@/lib/types";

const VERDICT = {
  clean: { label: "Clean", icon: ShieldCheck, cls: "bg-success/12 text-success ring-success/30" },
  suspicious: { label: "Suspicious", icon: ShieldQuestion, cls: "bg-warning/12 text-warning ring-warning/30" },
  malicious: { label: "Malicious", icon: ShieldAlert, cls: "bg-danger/12 text-danger ring-danger/30" },
};
const CAP_ICON = { network: Globe, filesystem: HardDrive, exec: Terminal, none: Cpu } as const;
const LAYER_LABEL: Record<string, string> = { rules: "Rules", prompt_guard: "Prompt Guard 2", llm: "LLM judge" };

export function ToolVerdictPill({ verdict, score }: { verdict: ToolVerdict["verdict"]; score?: number }) {
  const v = VERDICT[verdict];
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset", v.cls)}>
      <v.icon className="size-3.5" aria-hidden />
      {v.label}
      {score != null && score > 0 && <span className="font-mono font-normal opacity-80">{score.toFixed(2)}</span>}
    </span>
  );
}

export function ToolCard({ tool, verdict, defaultOpen }: { tool: ToolDef; verdict?: ToolVerdict; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? verdict?.verdict !== "clean");
  const highlightsFor = (field: string) => (verdict?.highlights ?? []).filter((h) => h.field === field || h.field.startsWith(`${field} (`)).map((h) => h.text);
  const props = Object.entries(tool.inputSchema?.properties ?? {});
  const required = new Set(tool.inputSchema?.required ?? []);
  const v = verdict?.verdict ?? "clean";
  // Collapse repeated rule hits (one per matched snippet) into one row per rule + field.
  const signals = (() => {
    const out: ToolSignal[] = [];
    const byKey = new Map<string, ToolSignal & { matches: string[] }>();
    for (const sig of verdict?.signals ?? []) {
      if (sig.layer !== "rules") {
        out.push(sig);
        continue;
      }
      const key = `${sig.rule}|${sig.field}`;
      const existing = byKey.get(key);
      if (existing) {
        if (sig.match) existing.matches.push(sig.match);
      } else {
        const entry = { ...sig, matches: sig.match ? [sig.match] : [] };
        byKey.set(key, entry);
        out.push(entry);
      }
    }
    return out as (ToolSignal & { matches?: string[] })[];
  })();

  return (
    <article className={cn("card-surface overflow-hidden", v === "malicious" && "ring-1 ring-danger/40", v === "suspicious" && "ring-1 ring-warning/30")}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left transition-colors hover:bg-muted/30 focus-visible:outline-2 focus-visible:outline-ring"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <code className="font-mono text-sm font-semibold">{tool.name}</code>
            <span className="text-xs text-muted-foreground">{props.length} param{props.length === 1 ? "" : "s"}</span>
          </div>
          {!open && <p className="mt-1 truncate text-sm text-muted-foreground">{tool.description.split("\n")[0]}</p>}
        </div>
        <div className="flex shrink-0 items-center gap-3">
          {verdict && <ToolVerdictPill verdict={verdict.verdict} score={verdict.score} />}
          <ChevronDown className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-180")} aria-hidden />
        </div>
      </button>

      {open && (
        <div className="space-y-5 border-t px-5 py-4">
          <div>
            <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Description</p>
            <div className="rounded-lg border bg-background px-3.5 py-3 text-[13px] leading-relaxed">
              <HighlightedText text={tool.description || "(empty)"} highlights={highlightsFor("description")} />
            </div>
          </div>

          {props.length > 0 && (
            <div>
              <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Parameters</p>
              <div className="overflow-x-auto rounded-lg border">
                <table className="w-full text-[13px]">
                  <thead className="bg-muted/40 text-xs text-muted-foreground">
                    <tr>
                      <th className="px-3 py-2 text-left font-medium">Name</th>
                      <th className="px-3 py-2 text-left font-medium">Type</th>
                      <th className="px-3 py-2 text-left font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {props.map(([name, spec]) => {
                      const hl = highlightsFor(`param:${name}`);
                      return (
                        <tr key={name} className={cn(hl.length > 0 && "bg-danger/5")}>
                          <td className="whitespace-nowrap px-3 py-2 align-top font-mono">
                            {name}
                            {required.has(name) && <span className="ml-1 text-danger" title="required">*</span>}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 align-top font-mono text-muted-foreground">
                            {spec.type ?? spec.anyOf?.map((a) => a.type).join(" | ") ?? "any"}
                          </td>
                          <td className="px-3 py-2 align-top">
                            {spec.description ? <HighlightedText text={spec.description} highlights={hl} mono={false} /> : <span className="text-muted-foreground">—</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {verdict && (
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Claimed behavior</p>
                <p className="text-sm">{verdict.claimed_behavior ?? <span className="text-muted-foreground">Inferred from keywords (LLM judge offline)</span>}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {verdict.claimed_capabilities.map((c) => {
                    const Icon = CAP_ICON[c as keyof typeof CAP_ICON] ?? Cpu;
                    return (
                      <span key={c} className="inline-flex items-center gap-1 rounded-md bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                        <Icon className="size-3" aria-hidden /> {c}
                      </span>
                    );
                  })}
                </div>
              </div>
              <div>
                <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Analyzer layers · {verdict.layers_used.map((l) => LAYER_LABEL[l] ?? l).join(" → ")}
                </p>
                {signals.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No signals. Every layer considered this definition benign.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {signals.map((sig, i) => (
                      <li key={i} className="flex gap-2 text-xs">
                        <span className="mt-0.5 shrink-0 rounded bg-indigo/15 px-1.5 py-px font-medium text-indigo">{LAYER_LABEL[sig.layer]}</span>
                        <span className="min-w-0 text-foreground/90">
                          {sig.layer === "rules" && (
                            <>
                              {sig.title} <span className="font-mono text-muted-foreground">[{sig.field}]</span>
                              {!!sig.matches?.length && <span className="mt-0.5 block truncate font-mono text-muted-foreground">{sig.matches.map((m) => `“${m}”`).join("  ")}</span>}
                              {sig.decoded && <span className="mt-0.5 block font-mono text-danger">decoded: {sig.decoded.slice(0, 160)}</span>}
                            </>
                          )}
                          {sig.layer === "prompt_guard" && <>Injection probability <span className="font-mono">{sig.score?.toFixed(2)}</span></>}
                          {sig.layer === "llm" && (
                            <>
                              <Sparkles className="mr-1 inline size-3" aria-hidden />
                              {sig.malicious ? "Malicious" : "Benign"} ({Math.round((sig.confidence ?? 0) * 100)}%): {sig.reason}
                            </>
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </article>
  );
}
