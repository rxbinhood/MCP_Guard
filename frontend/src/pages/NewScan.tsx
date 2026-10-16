import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, Bug, FolderGit2, GitBranch, Loader2, Radar, RotateCcw, ScanSearch, Sparkles, Zap } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { Card, PageHeader } from "@/components/common";
import { LogConsole, PipelineStepper, stepStates } from "@/components/Pipeline";
import { VERDICT_META, VerdictBadge } from "@/components/severity";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { duration } from "@/lib/format";
import { useHealth, useScan, useScanEvents } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import type { Verdict } from "@/lib/types";

const EXAMPLES = [
  { label: "clean_calc", target: "test_servers/clean_calc" },
  { label: "clean_notes", target: "test_servers/clean_notes" },
  { label: "vuln_shell", target: "test_servers/vuln_shell" },
  { label: "poisoned_weather", target: "test_servers/poisoned_weather" },
  { label: "rugpull_todo", target: "test_servers/rugpull_todo" },
];

function Toggle({ id, icon: Icon, title, description, checked, onChange, badge }: {
  id: string;
  icon: typeof Zap;
  title: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  badge?: React.ReactNode;
}) {
  return (
    <label
      htmlFor={id}
      className={cn(
        "flex cursor-pointer items-start gap-3 rounded-xl border p-4 transition-colors",
        checked ? "border-teal/40 bg-teal/5" : "hover:bg-muted/40",
      )}
    >
      <span className={cn("grid size-9 shrink-0 place-items-center rounded-lg ring-1 ring-inset", checked ? "bg-teal/15 text-teal ring-teal/30" : "bg-muted text-muted-foreground ring-border")}>
        <Icon className="size-4" aria-hidden />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2 text-sm font-medium">
          {title} {badge}
        </span>
        <span className="mt-0.5 block text-xs text-muted-foreground">{description}</span>
      </span>
      <Switch id={id} checked={checked} onCheckedChange={(v) => onChange(!!v)} />
    </label>
  );
}

export default function NewScan() {
  const [params, setParams] = useSearchParams();
  const scanId = params.get("id") ?? undefined;
  const [target, setTarget] = useState(params.get("target") ?? "");
  const [staticOn, setStatic] = useState(true);
  const [ai, setAi] = useState(true);
  const [dynamic, setDynamic] = useState(false);
  const qc = useQueryClient();
  const health = useHealth();
  const dockerOk = health.data?.engines.find((e) => e.id === "docker")?.ok ?? false;
  const aiOk = health.data?.ai_online ?? false;

  const { events, done } = useScanEvents(scanId);
  const scan = useScan(done ? scanId : undefined);
  const states = useMemo(() => stepStates(events), [events]);
  const finalEvent = [...events].reverse().find((e) => e.type === "scan" && (e.status === "done" || e.status === "failed"));
  const startedAt = events[0]?.ts;

  const start = useMutation({
    mutationFn: () => api.createScan({ target: target.trim(), static: staticOn, ai, dynamic }),
    onSuccess: ({ id }) => {
      setParams({ id });
      toast.success("Scan started", { description: target });
    },
    onError: (e: Error) => toast.error("Could not start scan", { description: e.message }),
  });

  useEffect(() => {
    if (done) {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["stats"] });
    }
  }, [done, qc]);

  const reset = () => {
    setParams({});
  };

  const isUrl = /^(https?:\/\/|git@)/.test(target.trim());
  const verdict = (finalEvent?.verdict ?? scan.data?.verdict) as Verdict | undefined;

  return (
    <>
      <PageHeader
        icon={Radar}
        title="New scan"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "New scan" }]}
        description="Audit an MCP server from a GitHub URL or a local folder. Code runs only inside a locked-down Docker sandbox."
      />

      {!scanId ? (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <Card className="overflow-hidden" bodyClassName="p-0">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (target.trim()) start.mutate();
              }}
              className="grid-bg border-b px-6 py-8 md:px-10 md:py-10"
            >
              <label htmlFor="target" className="mb-2 block text-sm font-medium">
                Server to audit
              </label>
              <div className="flex flex-col gap-3 md:flex-row">
                <div className="relative flex-1">
                  {isUrl ? (
                    <GitBranch className="pointer-events-none absolute left-4 top-1/2 size-5 -translate-y-1/2 text-muted-foreground" aria-hidden />
                  ) : (
                    <FolderGit2 className="pointer-events-none absolute left-4 top-1/2 size-5 -translate-y-1/2 text-muted-foreground" aria-hidden />
                  )}
                  <Input
                    id="target"
                    autoFocus
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://github.com/org/mcp-server  or  /path/to/server"
                    className="h-12 bg-background pl-12 font-mono text-[15px] md:text-[15px]"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </div>
                <Button type="submit" size="lg" className="h-12 px-6 text-[15px]" disabled={!target.trim() || start.isPending}>
                  {start.isPending ? <Loader2 className="animate-spin" /> : <ScanSearch />} Scan
                </Button>
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
                <span className="text-muted-foreground">Bundled test servers:</span>
                {EXAMPLES.map((ex) => (
                  <button
                    type="button"
                    key={ex.label}
                    onClick={() => setTarget(ex.target)}
                    className={cn(
                      "rounded-md border bg-card px-2 py-1 font-mono transition-colors hover:border-teal/40 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring",
                      target === ex.target ? "border-teal/50 text-foreground" : "text-muted-foreground",
                    )}
                  >
                    {ex.label}
                  </button>
                ))}
              </div>
            </form>
            <div className="grid gap-3 p-6 md:grid-cols-3">
              <Toggle id="opt-static" icon={Bug} title="Static analysis" description="Custom Semgrep MCP rules, Bandit, Gitleaks and built-in AST checks." checked={staticOn} onChange={setStatic} />
              <Toggle
                id="opt-ai"
                icon={Sparkles}
                title="AI description analysis"
                description="Prompt Guard 2 and the LLM judge read every tool & parameter description. Rules always run."
                checked={ai}
                onChange={setAi}
                badge={!aiOk && health.data ? <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[10px] font-medium text-warning">offline · rules only</span> : null}
              />
              <Toggle
                id="opt-dynamic"
                icon={Zap}
                title="Dynamic probing"
                description="Runs tools with generated inputs under strace with canary secrets planted."
                checked={dynamic}
                onChange={setDynamic}
                badge={!dockerOk && health.data ? <span className="rounded bg-danger/15 px-1.5 py-0.5 text-[10px] font-medium text-danger">needs Docker</span> : <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">slower</span>}
              />
            </div>
          </Card>
        </motion.div>
      ) : (
        <div className="space-y-4">
          <Card
            title={
              <span className="flex items-center gap-2">
                {!done && <Loader2 className="size-4 animate-spin text-teal" />}
                {done ? "Scan complete" : "Scanning…"}
              </span>
            }
            description={<span className="font-mono">{scanId}</span>}
            action={
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs tabular-nums text-muted-foreground">{duration(startedAt, finalEvent?.ts)}</span>
                <Button variant="outline" size="sm" onClick={reset}>
                  <RotateCcw /> New scan
                </Button>
              </div>
            }
          >
            <PipelineStepper states={states} />
          </Card>

          <AnimatePresence>
            {done && verdict && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn("flex flex-col gap-4 rounded-xl p-5 ring-1 ring-inset sm:flex-row sm:items-center sm:justify-between", VERDICT_META[verdict].bg, VERDICT_META[verdict].ring)}
              >
                <div className="flex items-center gap-4">
                  <VerdictBadge verdict={verdict} className="px-3 py-1 text-sm" />
                  <div>
                    <p className="text-sm font-medium">Risk score {finalEvent?.risk_score ?? scan.data?.risk_score}/100</p>
                    <p className="text-xs text-muted-foreground">{VERDICT_META[verdict].blurb}</p>
                  </div>
                </div>
                <Button nativeButton={false} render={<Link to={`/scans/${scanId}`} />}>
                  View full report <ArrowRight />
                </Button>
              </motion.div>
            )}
            {done && finalEvent?.status === "failed" && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="rounded-xl border border-danger/30 bg-danger/5 p-5 text-sm">
                <p className="font-medium text-danger">Scan failed</p>
                <p className="mt-1 text-muted-foreground">{finalEvent.error ?? "See the log for details."}</p>
              </motion.div>
            )}
          </AnimatePresence>

          <LogConsole events={events} live={!done} />
        </div>
      )}
    </>
  );
}
