import { motion } from "framer-motion";
import { Boxes, Download, FileJson, FileText, Loader2, ScanSearch, ShieldHalf, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { Card, EmptyState, ErrorState, PageHeader, SkeletonRows } from "@/components/common";
import { FindingDrawer } from "@/components/FindingDrawer";
import { FindingsTable } from "@/components/FindingsTable";
import { LogConsole, PipelineStepper, stepStates } from "@/components/Pipeline";
import { RiskGauge } from "@/components/RiskGauge";
import { SEVERITY_META, VERDICT_META } from "@/components/severity";
import { ToolCard } from "@/components/ToolCard";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { duration, formatDate, targetName } from "@/lib/format";
import { useScan, useScanEvents } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import { SEVERITIES, type Finding, type ScanResult as Result } from "@/lib/types";

const SHORT: Record<string, string> = { CRITICAL: "Crit", HIGH: "High", MEDIUM: "Med", LOW: "Low", INFO: "Info" };

function VerdictBanner({ result }: { result: Result }) {
  const v = VERDICT_META[result.verdict];
  const counts = useMemo(() => {
    const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<string, number>;
    result.findings.forEach((f) => (c[f.severity] += 1));
    return c;
  }, [result]);
  const flagged = result.tool_verdicts.filter((t) => t.verdict !== "clean").length;
  return (
    <motion.section
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn("relative overflow-hidden rounded-2xl p-6 ring-1 ring-inset md:p-8", v.bg, v.ring)}
    >
      <div className="pointer-events-none absolute -right-16 -top-16 size-64 rounded-full opacity-20 blur-3xl" style={{ background: v.hex }} aria-hidden />
      <div className="relative flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-start gap-5">
          <span className={cn("grid size-16 shrink-0 place-items-center rounded-2xl ring-1 ring-inset", v.bg, v.ring, v.text)}>
            <v.icon className="size-8" aria-hidden />
          </span>
          <div>
            <p className={cn("text-xs font-semibold uppercase tracking-[0.2em]", v.text)}>Verdict</p>
            <p className={cn("text-4xl font-bold tracking-tight", v.text)}>{v.label}</p>
            <p className="mt-1.5 max-w-lg text-sm text-foreground/80">{v.blurb}</p>
            <p className="mt-3 text-xs text-muted-foreground">
              {result.manifest?.tools.length ?? 0} tools via {result.manifest?.method ?? "—"} · {flagged} flagged by the description analyzer · scanned {formatDate(result.started_at)} in {duration(result.started_at, result.finished_at)}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-6">
          <RiskGauge score={result.risk_score} />
          <ul className="grid grid-cols-5 gap-2 sm:gap-3" aria-label="Findings by severity">
            {SEVERITIES.map((s) => {
              const m = SEVERITY_META[s];
              return (
                <li key={s} className="flex w-16 flex-col items-center rounded-xl bg-card/70 px-2 py-3 ring-1 ring-inset ring-border">
                  <m.icon className={cn("size-4", m.text)} aria-hidden />
                  <span className="mt-1 text-xl font-semibold tabular-nums">{counts[s]}</span>
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{SHORT[s]}</span>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </motion.section>
  );
}

function ExportMenu({ id }: { id: string }) {
  const download = (fmt: "md" | "json" | "sarif") => {
    const a = document.createElement("a");
    a.href = api.reportUrl(id, fmt);
    a.download = "";
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast.success(`Exporting ${fmt === "md" ? "Markdown" : fmt.toUpperCase()} report`);
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="outline" />}>
        <Download /> Export
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuItem onClick={() => download("md")}>
          <FileText /> Markdown <span className="ml-auto text-xs text-muted-foreground">humans</span>
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => download("json")}>
          <FileJson /> JSON <span className="ml-auto text-xs text-muted-foreground">machines</span>
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => download("sarif")}>
          <ShieldHalf /> SARIF 2.1.0 <span className="ml-auto text-xs text-muted-foreground">CI / GitHub</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function EngineList({ engines }: { engines: Result["engines"] }) {
  return (
    <ul className="grid gap-2 sm:grid-cols-2">
      {Object.entries(engines).map(([name, info]) => (
        <li key={name} className="flex items-start justify-between gap-3 rounded-lg border px-3 py-2">
          <div className="min-w-0">
            <p className="text-sm font-medium">{name}</p>
            <p className="truncate text-xs text-muted-foreground" title={info.detail}>{info.detail ?? "—"}</p>
          </div>
          <span className={cn("shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium",
            info.status === "online" ? "bg-success/12 text-success" : info.status === "disabled" ? "bg-muted text-muted-foreground" : "bg-warning/12 text-warning")}>
            {info.status}
          </span>
        </li>
      ))}
    </ul>
  );
}

export default function ScanResultPage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "findings";
  const navigate = useNavigate();
  const scan = useScan(id);
  const [selected, setSelected] = useState<Finding | null>(null);
  const timeline = tab === "timeline";
  const { events } = useScanEvents(timeline ? id : undefined);
  const result = scan.data?.result ?? null;
  const running = scan.data && ["queued", "running"].includes(scan.data.status);

  if (scan.isLoading) {
    return (
      <>
        <Skeleton className="mb-6 h-10 w-72" />
        <Skeleton className="h-48 w-full rounded-2xl" />
        <SkeletonRows className="mt-6" rows={6} />
      </>
    );
  }
  if (scan.isError) return <ErrorState error={scan.error} onRetry={() => scan.refetch()} />;
  if (!scan.data) return null;

  const title = scan.data.server_name || targetName(scan.data.target);
  return (
    <>
      <PageHeader
        icon={ScanSearch}
        title={title}
        crumbs={[{ label: "Scans", to: "/scans" }, { label: title }]}
        description={<span className="font-mono text-xs">{scan.data.target}</span>}
        actions={
          result && (
            <>
              <Button variant="ghost" size="icon" aria-label="Delete scan" onClick={async () => {
                await api.deleteScan(scan.data!.id);
                toast.success("Scan deleted");
                navigate("/scans");
              }}>
                <Trash2 />
              </Button>
              <Button variant="outline" nativeButton={false} render={<Link to={`/scan/new?target=${encodeURIComponent(scan.data.target)}`} />}>
                Re-scan
              </Button>
              <ExportMenu id={scan.data.id} />
            </>
          )
        }
      />

      {running && (
        <Card className="mb-4">
          <div className="flex items-center gap-3 text-sm">
            <Loader2 className="size-4 animate-spin text-teal" /> This scan is still running.
            <Button size="sm" variant="outline" nativeButton={false} render={<Link to={`/scan/new?id=${scan.data.id}`} />}>Watch live</Button>
          </div>
        </Card>
      )}
      {scan.data.status === "failed" && !result?.findings.length && (
        <ErrorState error={result?.error ?? "The scan failed before producing results."} className="mb-4" />
      )}

      {result && (
        <>
          {!result.error && <VerdictBanner result={result} />}
          <Tabs value={tab} onValueChange={(v) => setParams({ tab: String(v) }, { replace: true })} className="mt-6">
            <TabsList>
              <TabsTrigger value="findings">Findings <span className="ml-1.5 rounded bg-background/60 px-1.5 font-mono text-[11px]">{result.findings.length}</span></TabsTrigger>
              <TabsTrigger value="tools">Tools <span className="ml-1.5 rounded bg-background/60 px-1.5 font-mono text-[11px]">{result.manifest?.tools.length ?? 0}</span></TabsTrigger>
              <TabsTrigger value="timeline">Timeline</TabsTrigger>
            </TabsList>
            <TabsContent value="findings" className="mt-3">
              <Card bodyClassName="p-0">
                <FindingsTable findings={result.findings} onSelect={setSelected} />
              </Card>
            </TabsContent>
            <TabsContent value="tools" className="mt-3 space-y-3">
              {!result.manifest?.tools.length ? (
                <Card><EmptyState icon={Boxes} title="No tools" description="The server did not expose any tools." /></Card>
              ) : (
                result.manifest.tools.map((t) => (
                  <ToolCard key={t.name} tool={t} verdict={result.tool_verdicts.find((v) => v.tool === t.name)} />
                ))
              )}
            </TabsContent>
            <TabsContent value="timeline" className="mt-3 space-y-4">
              <Card title="Pipeline">
                <PipelineStepper states={stepStates([], result.modules)} />
              </Card>
              <Card title="Engines used" description="What was online for this scan">
                <EngineList engines={result.engines} />
              </Card>
              <LogConsole events={events} />
            </TabsContent>
          </Tabs>
        </>
      )}
      <FindingDrawer finding={selected} onOpenChange={(o) => !o && setSelected(null)} />
    </>
  );
}
