import { ArrowRight, Fingerprint, LayoutDashboard, Plus, ScanLine, ServerCog, ShieldAlert, Siren } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { SeverityDonut, SeverityStackedBars } from "@/components/charts";
import { Card, EmptyState, ErrorState, PageHeader, SkeletonRows, StatCard } from "@/components/common";
import { EngineStatusPanel } from "@/components/EngineStatusPanel";
import { SeverityBadge, StatusDot, VerdictBadge } from "@/components/severity";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SOURCE_LABEL, targetName, timeAgo } from "@/lib/format";
import { useScans, useStats } from "@/lib/hooks";
import { SEVERITIES, type Counts, type ScanSummary, type Source } from "@/lib/types";

function RecentScans({ scans }: { scans: ScanSummary[] }) {
  const navigate = useNavigate();
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="border-b text-xs text-muted-foreground">
          <tr>
            <th className="px-5 py-2.5 text-left font-medium">Server</th>
            <th className="px-3 py-2.5 text-left font-medium">Verdict</th>
            <th className="px-3 py-2.5 text-left font-medium">Risk</th>
            <th className="hidden px-3 py-2.5 text-left font-medium md:table-cell">Top severity</th>
            <th className="px-5 py-2.5 text-right font-medium">When</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {scans.map((s) => {
            const top = SEVERITIES.find((sev) => (s.counts?.[sev] ?? 0) > 0 && sev !== "INFO");
            return (
              <tr
                key={s.id}
                tabIndex={0}
                className="cursor-pointer transition-colors hover:bg-muted/40 focus-visible:bg-muted/50 focus-visible:outline-none"
                onClick={() => navigate(`/scans/${s.id}`)}
                onKeyDown={(e) => e.key === "Enter" && navigate(`/scans/${s.id}`)}
              >
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2.5">
                    <StatusDot status={s.status} />
                    <div className="min-w-0">
                      <p className="truncate font-medium">{s.server_name || targetName(s.target)}</p>
                      <p className="truncate font-mono text-[11px] text-muted-foreground">{targetName(s.target)}</p>
                    </div>
                  </div>
                </td>
                <td className="px-3 py-3">{s.status === "done" ? <VerdictBadge verdict={s.verdict} /> : <span className="text-xs capitalize text-muted-foreground">{s.status}</span>}</td>
                <td className="px-3 py-3 font-mono tabular-nums">{s.risk_score ?? "—"}</td>
                <td className="hidden px-3 py-3 md:table-cell">
                  {top ? (
                    <span className="flex items-center gap-1.5">
                      <SeverityBadge severity={top} compact />
                      <span className="text-xs text-muted-foreground">× {s.counts?.[top]}</span>
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">none</span>
                  )}
                </td>
                <td className="whitespace-nowrap px-5 py-3 text-right text-xs text-muted-foreground">{timeAgo(s.started_at)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function Dashboard() {
  const stats = useStats();
  const scans = useScans(8);
  const [view, setView] = useState<"module" | "time">("module");
  const s = stats.data;

  const moduleRows = useMemo(
    () =>
      (["static", "description", "dynamic", "pin_diff"] as Source[]).map((src) => ({
        label: SOURCE_LABEL[src],
        ...(s?.by_source[src] ?? {}),
      })),
    [s],
  );
  const timeRows = useMemo(
    () =>
      (s?.timeline ?? []).map((d) => ({
        label: new Date(`${d.date}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
        ...Object.fromEntries(SEVERITIES.map((sev) => [sev, Number(d[`f_${sev}`] ?? 0)])),
      })),
    [s],
  );

  return (
    <>
      <PageHeader
        icon={LayoutDashboard}
        title="Dashboard"
        description="Security posture of the MCP servers you have audited, across every module."
      />

      {stats.isError ? (
        <ErrorState error={stats.error} onRetry={() => stats.refetch()} />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Servers scanned" value={s?.servers_scanned ?? 0} icon={ServerCog} loading={stats.isLoading} hint={`${s?.total_scans ?? 0} scans in total`} />
          <StatCard label="Total findings" value={s?.total_findings ?? 0} icon={ScanLine} tone="indigo" loading={stats.isLoading} hint="Latest scan per server" />
          <StatCard
            label="Critical / High"
            value={s?.critical_high ?? 0}
            icon={ShieldAlert}
            tone={s && s.critical_high > 0 ? "danger" : "success"}
            loading={stats.isLoading}
            hint={s && s.critical_high > 0 ? "Blocks connecting these servers" : "Nothing blocking"}
          />
          <StatCard
            label="Pinned servers"
            value={s?.pinned_servers ?? 0}
            icon={Fingerprint}
            tone={s && s.changed_pins > 0 ? "warning" : "teal"}
            loading={stats.isLoading}
            hint={s && s.changed_pins > 0 ? `${s.changed_pins} changed since pin` : "All fingerprints match"}
          />
        </div>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2" title="Findings by severity" description="Latest scan of each server">
          {stats.isLoading || !s ? <Skeleton className="h-44 w-full" /> : <SeverityDonut counts={s.severity as Counts} />}
        </Card>
        <Card
          className="lg:col-span-3"
          title={view === "module" ? "Findings per module" : "Findings over time"}
          description={view === "module" ? "Which engine caught what" : "Daily totals across all scans"}
          action={
            <Tabs value={view} onValueChange={(v) => setView(v as "module" | "time")}>
              <TabsList>
                <TabsTrigger value="module">By module</TabsTrigger>
                <TabsTrigger value="time">Over time</TabsTrigger>
              </TabsList>
            </Tabs>
          }
        >
          {stats.isLoading || !s ? <Skeleton className="h-[220px] w-full" /> : <SeverityStackedBars rows={view === "module" ? moduleRows : timeRows} />}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card
          className="lg:col-span-2"
          title="Recent scans"
          action={
            <Button variant="ghost" size="sm" nativeButton={false} render={<Link to="/scans" />}>
              View all <ArrowRight />
            </Button>
          }
          bodyClassName="p-0"
        >
          {scans.isLoading ? (
            <SkeletonRows className="p-5" />
          ) : scans.isError ? (
            <ErrorState error={scans.error} onRetry={() => scans.refetch()} className="m-5" />
          ) : !scans.data?.length ? (
            <EmptyState
              icon={Siren}
              title="No scans yet"
              description="Point MCPGuard at a GitHub URL or a local folder to audit your first MCP server."
              action={<Button nativeButton={false} render={<Link to="/scan/new" />}><Plus /> Start a scan</Button>}
            />
          ) : (
            <RecentScans scans={scans.data} />
          )}
        </Card>
        <EngineStatusPanel />
      </div>
    </>
  );
}
