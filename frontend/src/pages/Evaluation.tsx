import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileQuestion, FlaskConical, Loader2, Play, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { Card, EmptyState, ErrorState, Mono, PageHeader, SkeletonRows } from "@/components/common";
import { VerdictBadge } from "@/components/severity";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { SOURCE_LABEL, pct, timeAgo } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { EvalMode } from "@/lib/types";

const MODE_LABEL: Record<string, string> = { rules: "Rules only", full: "Rules + Prompt Guard + LLM" };

function Meter({ label, value, good, hint }: { label: string; value: number; good: "high" | "low"; hint: string }) {
  const ok = good === "high" ? value >= 0.8 : value <= 0.1;
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span className={cn("font-mono text-lg font-semibold tabular-nums", ok ? "text-success" : "text-warning")}>{pct(value)}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-muted" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(value * 100)} aria-label={label}>
        <div className={cn("h-full rounded-full", good === "high" ? "bg-teal" : "bg-sev-high")} style={{ width: `${Math.max(1, value * 100)}%` }} />
      </div>
      <p className="mt-1 text-[11px] text-muted-foreground">{hint}</p>
    </div>
  );
}

function ModeCard({ mode, m }: { mode: string; m: EvalMode }) {
  return (
    <div className="rounded-xl border bg-card p-5">
      <div className="mb-4 flex items-start justify-between gap-2">
        <div>
          <p className="font-medium">{MODE_LABEL[mode] ?? mode}</p>
          <p className="text-xs text-muted-foreground">layers online: {m.layers.join(", ") || "rules"}</p>
        </div>
        <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-muted-foreground">n={m.n}</span>
      </div>
      <div className="space-y-4">
        <Meter label="Detection rate" value={m.detection_rate} good="high" hint={`${m.tp} of ${m.tp + m.fn} malicious samples flagged`} />
        <Meter label="False-positive rate" value={m.false_positive_rate} good="low" hint={`${m.fp} of ${m.fp + m.tn} benign samples flagged`} />
      </div>
      <dl className="mt-4 grid grid-cols-4 gap-2 border-t pt-4 text-center">
        {[["TP", m.tp], ["FN", m.fn], ["FP", m.fp], ["TN", m.tn]].map(([k, v]) => (
          <div key={k}>
            <dt className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{k}</dt>
            <dd className="font-mono text-base tabular-nums">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export default function Evaluation() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["eval"],
    queryFn: api.eval,
    refetchInterval: (query) => (query.state.data?.state.running ? 2000 : false),
  });
  const run = useMutation({
    mutationFn: () => api.runEval(true),
    onSuccess: () => {
      toast("Evaluation started", { description: "Scanning all five test servers and the labeled samples…" });
      qc.invalidateQueries({ queryKey: ["eval"] });
    },
    onError: (e: Error) => toast.error("Could not start evaluation", { description: e.message }),
  });

  const res = q.data?.results;
  const running = q.data?.state.running || run.isPending;
  const servers = res?.servers ?? [];
  const correct = servers.filter((s) => s.passed).length;
  const desc = res?.descriptions;

  return (
    <>
      <PageHeader
        icon={FlaskConical}
        title="Evaluation"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Evaluation" }]}
        description="Ground-truth checks: the five bundled test servers with planted issues, plus a labeled set of tool descriptions for detection and false-positive rates."
        actions={
          <Button onClick={() => run.mutate()} disabled={running}>
            {running ? <Loader2 className="animate-spin" /> : <Play />} {running ? "Running…" : "Run evaluation"}
          </Button>
        }
      />
      {q.isLoading ? (
        <SkeletonRows rows={6} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} />
      ) : (
        <div className="space-y-4">
          {q.data?.state.error && <ErrorState error={q.data.state.error} />}

          <Card
            title="Test servers"
            description={res ? `Last run ${timeAgo(res.generated_at)}` : "Not run yet; showing the expected outcomes"}
            action={
              servers.length > 0 && (
                <span className={cn("rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset", correct === servers.length ? "bg-success/12 text-success ring-success/30" : "bg-danger/12 text-danger ring-danger/30")}>
                  {correct}/{servers.length} correct
                </span>
              )
            }
            bodyClassName="p-0"
          >
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
                  <tr>
                    <th className="px-4 py-2.5 text-left font-medium">Server</th>
                    <th className="px-3 py-2.5 text-left font-medium">Planted issue</th>
                    <th className="px-3 py-2.5 text-left font-medium">Caught by</th>
                    <th className="px-3 py-2.5 text-left font-medium">Expected</th>
                    <th className="px-3 py-2.5 text-left font-medium">Verdict</th>
                    <th className="px-4 py-2.5 text-right font-medium">Result</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {(servers.length ? servers : q.data?.expected ?? []).map((s) => {
                    const r = servers.find((x) => x.server === s.server);
                    return (
                      <tr key={s.server}>
                        <td className="px-4 py-3"><Mono>{s.server}</Mono></td>
                        <td className="max-w-sm px-3 py-3 text-muted-foreground">{s.planted}</td>
                        <td className="px-3 py-3">
                          <div className="flex flex-wrap gap-1">
                            {r?.caught_by.length ? r.caught_by.map((c) => (
                              <span key={c} className="rounded bg-indigo/12 px-1.5 py-0.5 text-[11px] font-medium text-indigo">{SOURCE_LABEL[c]}</span>
                            )) : <span className="text-xs text-muted-foreground">—</span>}
                          </div>
                        </td>
                        <td className="px-3 py-3"><VerdictBadge verdict={s.expected} /></td>
                        <td className="px-3 py-3">{r ? (
                          <Link to={`/scans/${r.scan_id}`} className="rounded focus-visible:outline-2"><VerdictBadge verdict={r.verdict} /></Link>
                        ) : <span className="text-xs text-muted-foreground">not run</span>}</td>
                        <td className="px-4 py-3 text-right">
                          {r ? (r.passed ? (
                            <span className="inline-flex items-center gap-1 text-xs font-medium text-success"><CheckCircle2 className="size-4" /> Pass</span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs font-medium text-danger"><XCircle className="size-4" /> Mismatch</span>
                          )) : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title="Description test set" description={desc?.available ? `Threshold: score ≥ ${desc.threshold} counts as detected (MEDIUM or worse)` : undefined}>
            {!res ? (
              <EmptyState icon={Play} title="No results yet" description="Run the evaluation to compute detection and false-positive rates." />
            ) : !desc?.available ? (
              <EmptyState
                icon={FileQuestion}
                title="Labeled samples not found"
                description={
                  <>
                    Add <Mono>tests/description_samples.json</Mono> as a list of <Mono>{`{id, text, label: "benign" | "malicious", kind}`}</Mono> objects, then re-run. ({desc?.reason})
                  </>
                }
              />
            ) : (
              <div className="space-y-5">
                <div className="grid gap-4 md:grid-cols-2">
                  {Object.entries(desc.modes ?? {}).map(([mode, m]) => <ModeCard key={mode} mode={mode} m={m} />)}
                </div>
                {desc.by_kind && (
                  <div className="overflow-x-auto rounded-lg border">
                    <table className="w-full text-sm">
                      <thead className="bg-muted/40 text-xs text-muted-foreground">
                        <tr>
                          <th className="px-3 py-2 text-left font-medium">Sample kind</th>
                          <th className="px-3 py-2 text-right font-medium">Samples</th>
                          <th className="px-3 py-2 text-right font-medium">Flagged</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y">
                        {Object.entries(desc.by_kind).map(([k, v]) => (
                          <tr key={k}>
                            <td className="px-3 py-2 font-mono text-xs">{k}</td>
                            <td className="px-3 py-2 text-right tabular-nums">{v.total}</td>
                            <td className="px-3 py-2 text-right tabular-nums">{v.flagged}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
