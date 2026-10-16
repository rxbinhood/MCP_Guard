import { Boxes, Plus, ServerCog } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Card, EmptyState, ErrorState, PageHeader, SkeletonRows } from "@/components/common";
import { VerdictBadge } from "@/components/severity";
import { ToolCard } from "@/components/ToolCard";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { targetName, timeAgo } from "@/lib/format";
import { useScan, useScans } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import type { ScanSummary } from "@/lib/types";

export default function ToolsInspector() {
  const scans = useScans(200);
  const [params, setParams] = useSearchParams();
  const [flaggedOnly, setFlaggedOnly] = useState(false);

  // Latest finished scan per target.
  const servers = useMemo(() => {
    const latest = new Map<string, ScanSummary>();
    for (const s of scans.data ?? []) if (s.status === "done" && !latest.has(s.target)) latest.set(s.target, s);
    return [...latest.values()];
  }, [scans.data]);

  const selectedId = params.get("scan") ?? servers[0]?.id;
  const scan = useScan(selectedId);
  const result = scan.data?.result;
  const verdicts = result?.tool_verdicts ?? [];
  const tools = (result?.manifest?.tools ?? []).filter(
    (t) => !flaggedOnly || verdicts.find((v) => v.tool === t.name)?.verdict !== "clean",
  );
  const summary = {
    malicious: verdicts.filter((v) => v.verdict === "malicious").length,
    suspicious: verdicts.filter((v) => v.verdict === "suspicious").length,
    clean: verdicts.filter((v) => v.verdict === "clean").length,
  };

  return (
    <>
      <PageHeader
        icon={Boxes}
        title="Tools inspector"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Tools inspector" }]}
        description="Everything an AI agent reads before calling a tool (name, description, parameter schema) with the analyzer's verdict. Poisoned text is highlighted inline; invisible characters are revealed."
      />
      {scans.isError ? (
        <ErrorState error={scans.error} onRetry={() => scans.refetch()} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
          <Card title="Servers" description="Latest scan of each" bodyClassName="p-2">
            {scans.isLoading ? (
              <SkeletonRows className="p-3" rows={5} />
            ) : !servers.length ? (
              <EmptyState icon={ServerCog} title="No servers yet" description="Scan a server to inspect its tools." action={<Button size="sm" nativeButton={false} render={<Link to="/scan/new" />}><Plus /> New scan</Button>} />
            ) : (
              <ul className="space-y-0.5" role="listbox" aria-label="Servers">
                {servers.map((s) => (
                  <li key={s.id}>
                    <button
                      role="option"
                      aria-selected={s.id === selectedId}
                      onClick={() => setParams({ scan: s.id })}
                      className={cn(
                        "flex w-full items-center justify-between gap-2 rounded-lg px-3 py-2.5 text-left transition-colors focus-visible:outline-2 focus-visible:outline-ring",
                        s.id === selectedId ? "bg-accent text-accent-foreground" : "hover:bg-muted/50",
                      )}
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">{s.server_name || targetName(s.target)}</span>
                        <span className="block text-[11px] text-muted-foreground">{timeAgo(s.started_at)}</span>
                      </span>
                      <VerdictBadge verdict={s.verdict} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <div className="min-w-0 space-y-3">
            {scan.isLoading || (!result && selectedId) ? (
              <SkeletonRows rows={4} />
            ) : result ? (
              <>
                <div className="card-surface flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
                  <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
                    <span className="font-medium">{result.server_name}</span>
                    <span className="text-danger">{summary.malicious} malicious</span>
                    <span className="text-warning">{summary.suspicious} suspicious</span>
                    <span className="text-success">{summary.clean} clean</span>
                    <span className="text-xs text-muted-foreground">manifest via {result.manifest?.method}</span>
                  </div>
                  <label className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Switch checked={flaggedOnly} onCheckedChange={(v) => setFlaggedOnly(!!v)} aria-label="Show flagged tools only" />
                    Flagged only
                  </label>
                </div>
                {tools.length ? (
                  tools.map((t) => <ToolCard key={`${selectedId}-${t.name}`} tool={t} verdict={verdicts.find((v) => v.tool === t.name)} />)
                ) : (
                  <Card><EmptyState icon={Boxes} title={flaggedOnly ? "No flagged tools" : "No tools"} description={flaggedOnly ? "Every tool definition on this server looks benign." : "This server exposes no tools."} /></Card>
                )}
              </>
            ) : null}
          </div>
        </div>
      )}
    </>
  );
}
