import { ListChecks, Plus, Search, Siren } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Card, EmptyState, ErrorState, PageHeader, SkeletonRows } from "@/components/common";
import { SEVERITY_META, StatusDot, VerdictBadge } from "@/components/severity";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { duration, formatDate, targetName } from "@/lib/format";
import { useScans } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import { SEVERITIES, type Verdict } from "@/lib/types";

const FILTERS: (Verdict | "ALL")[] = ["ALL", "FAIL", "WARN", "PASS"];

export default function Scans() {
  const scans = useScans(200);
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [verdict, setVerdict] = useState<Verdict | "ALL">("ALL");

  const rows = useMemo(
    () =>
      (scans.data ?? []).filter(
        (s) =>
          (verdict === "ALL" || s.verdict === verdict) &&
          (!q || `${s.server_name} ${s.target} ${s.id}`.toLowerCase().includes(q.toLowerCase())),
      ),
    [scans.data, q, verdict],
  );

  return (
    <>
      <PageHeader
        icon={ListChecks}
        title="Scans"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Scans" }]}
        description="Every audit run from the UI or the CLI."
        actions={<Button nativeButton={false} render={<Link to="/scan/new" />}><Plus /> New scan</Button>}
      />
      <Card bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-3 border-b px-4 py-3">
          <div className="relative min-w-56 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by server, path or scan ID" className="h-8 pl-8" aria-label="Filter scans" />
          </div>
          <div role="radiogroup" aria-label="Verdict filter" className="flex rounded-lg bg-muted p-0.5">
            {FILTERS.map((f) => (
              <button
                key={f}
                role="radio"
                aria-checked={verdict === f}
                onClick={() => setVerdict(f)}
                className={cn("rounded-md px-3 py-1 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-ring",
                  verdict === f ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}
              >
                {f === "ALL" ? "All" : f}
              </button>
            ))}
          </div>
        </div>
        {scans.isLoading ? (
          <SkeletonRows className="p-5" rows={8} />
        ) : scans.isError ? (
          <ErrorState error={scans.error} onRetry={() => scans.refetch()} className="m-5" />
        ) : !scans.data?.length ? (
          <EmptyState icon={Siren} title="No scans yet" description="Run your first audit to see results here." action={<Button nativeButton={false} render={<Link to="/scan/new" />}><Plus /> New scan</Button>} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 text-left font-medium">Server</th>
                  <th className="px-3 py-2.5 text-left font-medium">Verdict</th>
                  <th className="px-3 py-2.5 text-left font-medium">Risk</th>
                  <th className="px-3 py-2.5 text-left font-medium">Findings</th>
                  <th className="hidden px-3 py-2.5 text-left font-medium lg:table-cell">Modules</th>
                  <th className="px-3 py-2.5 text-left font-medium">Started</th>
                  <th className="hidden px-4 py-2.5 text-right font-medium md:table-cell">Duration</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {rows.map((s) => (
                  <tr key={s.id} tabIndex={0} onClick={() => navigate(`/scans/${s.id}`)} onKeyDown={(e) => e.key === "Enter" && navigate(`/scans/${s.id}`)}
                    className="cursor-pointer transition-colors hover:bg-muted/40 focus-visible:bg-muted/50 focus-visible:outline-none">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <StatusDot status={s.status} />
                        <div className="min-w-0">
                          <p className="truncate font-medium">{s.server_name || targetName(s.target)}</p>
                          <p className="truncate font-mono text-[11px] text-muted-foreground">{s.id}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-3">{s.status === "done" ? <VerdictBadge verdict={s.verdict} /> : <span className="text-xs capitalize text-muted-foreground">{s.status}</span>}</td>
                    <td className="px-3 py-3 font-mono tabular-nums">{s.risk_score ?? "—"}</td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        {SEVERITIES.filter((sev) => (s.counts?.[sev] ?? 0) > 0).map((sev) => {
                          const m = SEVERITY_META[sev];
                          return (
                            <span key={sev} className={cn("inline-flex items-center gap-0.5 text-xs font-medium", m.text)} title={`${s.counts?.[sev]} ${sev}`}>
                              <m.icon className="size-3.5" aria-hidden />
                              <span className="tabular-nums">{s.counts?.[sev]}</span>
                              <span className="sr-only">{sev}</span>
                            </span>
                          );
                        })}
                        {!SEVERITIES.some((sev) => (s.counts?.[sev] ?? 0) > 0) && <span className="text-xs text-muted-foreground">none</span>}
                      </div>
                    </td>
                    <td className="hidden px-3 py-3 lg:table-cell">
                      <div className="flex gap-1">
                        {(["static", "ai", "dynamic"] as const).map((k) => (
                          <span key={k} className={cn("rounded px-1.5 py-0.5 text-[10px] font-medium", s.options?.[k] ? "bg-teal/12 text-teal" : "bg-muted text-muted-foreground line-through")}>
                            {k === "ai" ? "AI" : k}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-xs text-muted-foreground">{formatDate(s.started_at)}</td>
                    <td className="hidden whitespace-nowrap px-4 py-3 text-right font-mono text-xs text-muted-foreground md:table-cell">{duration(s.started_at, s.finished_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!rows.length && <p className="px-4 py-10 text-center text-sm text-muted-foreground">No scans match these filters.</p>}
          </div>
        )}
      </Card>
    </>
  );
}
