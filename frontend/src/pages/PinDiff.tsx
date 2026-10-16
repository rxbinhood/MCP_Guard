import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertOctagon,
  CheckCircle2,
  Fingerprint,
  FlaskConical,
  GitCompareArrows,
  Loader2,
  Pin,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Card, EmptyState, ErrorState, PageHeader, SkeletonRows } from "@/components/common";
import { DiffView } from "@/components/DiffView";
import { HighlightedText } from "@/components/HighlightedText";
import { SeverityBadge } from "@/components/severity";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import { formatDate, shortHash, timeAgo } from "@/lib/format";
import { usePins } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import type { Finding, ManifestDiff, PinSummary } from "@/lib/types";

type CheckView = { status: string; diff: ManifestDiff | null; findings: Finding[]; rug_pull: boolean; ts: number; error?: string | null };

function PinStatus({ status }: { status: PinSummary["last_status"] }) {
  const map = {
    unchanged: { label: "Unchanged", icon: CheckCircle2, cls: "bg-success/12 text-success ring-success/30" },
    changed: { label: "Changed", icon: AlertOctagon, cls: "bg-danger/12 text-danger ring-danger/30" },
    error: { label: "Error", icon: AlertOctagon, cls: "bg-warning/12 text-warning ring-warning/30" },
    pinned: { label: "Pinned", icon: Pin, cls: "bg-indigo/12 text-indigo ring-indigo/30" },
  } as const;
  const m = map[(status ?? "pinned") as keyof typeof map] ?? map.pinned;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset", m.cls)}>
      <m.icon className="size-3.5" aria-hidden /> {m.label}
    </span>
  );
}

function RugPullBanner({ check }: { check: CheckView }) {
  return (
    <motion.div
      role="alert"
      initial={{ opacity: 0, scale: 0.98, y: -6 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      className="relative overflow-hidden rounded-2xl bg-danger/12 p-6 ring-2 ring-inset ring-danger/50"
    >
      <motion.div
        className="pointer-events-none absolute inset-0 bg-danger/10"
        animate={{ opacity: [0.2, 0.6, 0.2] }}
        transition={{ duration: 2.4, repeat: Infinity }}
        aria-hidden
      />
      <div className="relative flex items-start gap-4">
        <span className="grid size-12 shrink-0 place-items-center rounded-xl bg-danger text-white shadow-lg shadow-danger/30">
          <AlertOctagon className="size-6" aria-hidden />
        </span>
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity="CRITICAL" />
            <p className="text-xl font-bold tracking-tight text-danger">Rug pull detected</p>
          </div>
          <p className="mt-1 text-sm text-foreground/90">{check.diff?.summary}</p>
          <p className="mt-1 text-sm text-muted-foreground">
            The new tool definition contains instructions aimed at the AI agent. Disconnect this server from your agents and do not re-approve it.
          </p>
        </div>
      </div>
    </motion.div>
  );
}

function CheckDetail({ check }: { check: CheckView }) {
  if (check.status === "error") return <ErrorState error={check.error ?? "Verification failed"} />;
  if (check.status !== "changed" || !check.diff) {
    return (
      <div className="flex items-center gap-3 rounded-xl bg-success/8 p-5 ring-1 ring-inset ring-success/30">
        <ShieldCheck className="size-6 text-success" aria-hidden />
        <div>
          <p className="font-medium text-success">Unchanged</p>
          <p className="text-sm text-muted-foreground">
            The live manifest matches the pinned fingerprint <code className="font-mono">{shortHash(check.diff?.new_hash, 16)}</code>. Checked {timeAgo(check.ts)}.
          </p>
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      {check.rug_pull && <RugPullBanner check={check} />}
      {!check.rug_pull && (
        <div className="rounded-xl bg-warning/10 p-5 ring-1 ring-inset ring-warning/30">
          <p className="font-medium text-warning">Definitions changed</p>
          <p className="text-sm text-muted-foreground">{check.diff.summary}</p>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        {[
          { label: "Changed", items: check.diff.changed, tone: "text-warning" },
          { label: "Added", items: check.diff.added, tone: "text-success" },
          { label: "Removed", items: check.diff.removed, tone: "text-danger" },
        ].map((g) => (
          <div key={g.label} className="rounded-xl border bg-card px-4 py-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{g.label}</p>
            <p className={cn("mt-1 text-2xl font-semibold tabular-nums", g.items.length ? g.tone : "text-muted-foreground")}>{g.items.length}</p>
            <p className="truncate font-mono text-xs text-muted-foreground">{g.items.join(", ") || "—"}</p>
          </div>
        ))}
      </div>

      {check.diff.tools.map((t) => {
        const finding = check.findings.find((f) => f.tool === t.tool);
        return (
          <Card
            key={t.tool}
            title={
              <span className="flex items-center gap-2">
                <code className="font-mono">{t.tool}</code>
                <span className="text-xs font-normal capitalize text-muted-foreground">{t.status}</span>
              </span>
            }
            description={
              <span className="font-mono">
                {shortHash(t.old_hash)} → {shortHash(t.new_hash)}
              </span>
            }
            action={finding && <SeverityBadge severity={finding.severity} />}
          >
            {t.fields.length > 0 && (
              <div className="mb-3 flex flex-wrap gap-1.5">
                {t.fields.map((f) => (
                  <span key={f.path} className="rounded-md bg-muted px-2 py-0.5 font-mono text-[11px] text-muted-foreground">
                    {f.kind}: {f.path}
                  </span>
                ))}
              </div>
            )}
            <DiffView oldText={t.old_text} newText={t.new_text} oldLabel="Pinned (approved)" newLabel="Live (now)" />
            {finding && (
              <div className="mt-4 rounded-xl border p-4">
                <p className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Analyzer re-verdict on changed text</p>
                <p className="text-sm font-medium">{finding.title}</p>
                <pre className="mt-2 max-h-48 overflow-auto rounded-lg bg-background p-3 text-[12px] scrollbar-thin">
                  <HighlightedText text={finding.evidence} highlights={finding.highlights} />
                </pre>
                <p className="mt-3 text-sm text-muted-foreground">
                  <span className="font-medium text-foreground">Fix: </span>
                  {finding.fix}
                </p>
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}

export default function PinDiff() {
  const qc = useQueryClient();
  const pins = usePins();
  const [target, setTarget] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [checks, setChecks] = useState<Record<string, CheckView>>({});
  const demo = useQuery({ queryKey: ["rugpull"], queryFn: api.rugpull });

  useEffect(() => {
    if (!selected && pins.data?.length) setSelected(pins.data[0].server_key);
  }, [pins.data, selected]);

  // Load the most recent stored check for the selected pin so the page survives reloads.
  const detail = useQuery({ queryKey: ["pin", selected], queryFn: () => api.pinDetail(selected!), enabled: !!selected });
  const current: CheckView | undefined = useMemo(() => {
    if (selected && checks[selected]) return checks[selected];
    const c = detail.data?.checks?.[0];
    return c ? { status: c.status, diff: c.diff, findings: c.findings, rug_pull: c.findings.some((f) => f.severity === "CRITICAL"), ts: c.ts } : undefined;
  }, [selected, checks, detail.data]);

  const pin = useMutation({
    mutationFn: (t: string) => api.pin(t),
    onSuccess: (p) => {
      toast.success(`Pinned ${p.server_name}`, { description: `Fingerprint ${shortHash(p.manifest_hash, 16)}` });
      setTarget("");
      setSelected(p.server_key);
      qc.invalidateQueries({ queryKey: ["pins"] });
      qc.invalidateQueries({ queryKey: ["stats"] });
    },
    onError: (e: Error) => toast.error("Pin failed", { description: e.message }),
  });

  const verify = useMutation({
    mutationFn: (key: string) => api.verify(key),
    onMutate: (key) => setSelected(key),
    onSuccess: (r, key) => {
      setChecks((c) => ({ ...c, [key]: { ...r, ts: r.checked_at } }));
      qc.invalidateQueries({ queryKey: ["pins"] });
      qc.invalidateQueries({ queryKey: ["pin", key] });
      qc.invalidateQueries({ queryKey: ["stats"] });
      if (r.rug_pull) toast.error("Rug pull detected", { description: r.diff?.summary });
      else if (r.status === "changed") toast.warning("Definitions changed", { description: r.diff?.summary });
      else if (r.status === "unchanged") toast.success(`${r.server_name} is unchanged`);
      else toast.error("Verification failed", { description: r.error ?? undefined });
    },
    onError: (e: Error) => toast.error("Verification failed", { description: e.message }),
  });

  const toggle = useMutation({
    mutationFn: (armed: boolean) => api.setRugpull(armed),
    onSuccess: (s) => {
      qc.setQueryData(["rugpull"], s);
      toast(s.armed ? "rugpull_todo armed" : "rugpull_todo disarmed", {
        description: s.armed ? "Its next tools/list returns a poisoned add_todo description." : "The server is back to its clean definition.",
      });
    },
  });

  const unpin = useMutation({
    mutationFn: (key: string) => api.unpin(key),
    onSuccess: () => {
      setSelected(null);
      qc.invalidateQueries({ queryKey: ["pins"] });
      toast.success("Pin removed");
    },
  });

  const selectedPin = pins.data?.find((p) => p.server_key === selected);

  return (
    <>
      <PageHeader
        icon={GitCompareArrows}
        title="Pin & Diff"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Pin & Diff" }]}
        description="Fingerprint a server's tool manifest when you approve it. Verify later to catch silent changes (rug pulls), with a field-level diff and a fresh AI verdict on the changed text."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Pin a server" description="SHA-256 per tool + one hash for the whole canonicalized manifest">
          <form
            className="flex flex-col gap-2 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              if (target.trim()) pin.mutate(target.trim());
            }}
          >
            <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="test_servers/rugpull_todo or a GitHub URL" className="h-9 font-mono" aria-label="Server to pin" />
            <Button type="submit" className="h-9" disabled={!target.trim() || pin.isPending}>
              {pin.isPending ? <Loader2 className="animate-spin" /> : <Fingerprint />} Pin
            </Button>
          </form>
        </Card>
        <Card title={<span className="flex items-center gap-2"><FlaskConical className="size-4 text-indigo" /> Rug-pull demo</span>} description="Flips the toggle file of the bundled rugpull_todo server">
          <label className="flex items-center justify-between gap-3">
            <span className="text-sm">
              {demo.data?.armed ? <span className="font-medium text-danger">Armed: next tools/list is poisoned</span> : <span className="text-muted-foreground">Disarmed: server is clean</span>}
            </span>
            <Switch checked={!!demo.data?.armed} disabled={toggle.isPending || demo.isLoading} onCheckedChange={(v) => toggle.mutate(!!v)} aria-label="Arm rug pull" />
          </label>
        </Card>
      </div>

      <Card className="mt-4" title="Pinned servers" bodyClassName="p-0">
        {pins.isLoading ? (
          <SkeletonRows className="p-5" rows={3} />
        ) : pins.isError ? (
          <ErrorState error={pins.error} onRetry={() => pins.refetch()} className="m-5" />
        ) : !pins.data?.length ? (
          <EmptyState icon={Fingerprint} title="Nothing pinned yet" description="Pin a server above to start watching it for rug pulls." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 text-left font-medium">Server</th>
                  <th className="px-3 py-2.5 text-left font-medium">Fingerprint</th>
                  <th className="px-3 py-2.5 text-left font-medium">Tools</th>
                  <th className="hidden px-3 py-2.5 text-left font-medium md:table-cell">Pinned</th>
                  <th className="px-3 py-2.5 text-left font-medium">Status</th>
                  <th className="hidden px-3 py-2.5 text-left font-medium md:table-cell">Last verified</th>
                  <th className="px-4 py-2.5 text-right font-medium"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {pins.data.map((p) => (
                  <tr key={p.server_key} onClick={() => setSelected(p.server_key)} className={cn("cursor-pointer transition-colors hover:bg-muted/40", p.server_key === selected && "bg-accent/40")}>
                    <td className="px-4 py-3">
                      <p className="font-medium">{p.server_name}</p>
                      <p className="max-w-64 truncate font-mono text-[11px] text-muted-foreground" title={p.target}>{p.target}</p>
                    </td>
                    <td className="px-3 py-3">
                      <Tooltip>
                        <TooltipTrigger className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{shortHash(p.manifest_hash)}</TooltipTrigger>
                        <TooltipContent className="font-mono text-[11px]">{p.manifest_hash}</TooltipContent>
                      </Tooltip>
                    </td>
                    <td className="px-3 py-3 tabular-nums">{p.tools}</td>
                    <td className="hidden whitespace-nowrap px-3 py-3 text-xs text-muted-foreground md:table-cell">{formatDate(p.pinned_at)}</td>
                    <td className="px-3 py-3"><PinStatus status={p.last_status} /></td>
                    <td className="hidden px-3 py-3 text-xs text-muted-foreground md:table-cell">{timeAgo(p.last_verified_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            verify.mutate(p.server_key);
                          }}
                          disabled={verify.isPending}
                        >
                          {verify.isPending && verify.variables === p.server_key ? <Loader2 className="animate-spin" /> : <RefreshCw />} Verify now
                        </Button>
                        <Button
                          size="icon-sm"
                          variant="ghost"
                          aria-label={`Remove pin for ${p.server_name}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            unpin.mutate(p.server_key);
                          }}
                        >
                          <Trash2 />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selectedPin && (
        <section className="mt-6" aria-live="polite">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
            Latest verification · <span className="font-normal text-muted-foreground">{selectedPin.server_name}</span>
          </h2>
          <AnimatePresence mode="wait">
            {verify.isPending && verify.variables === selectedPin.server_key ? (
              <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="card-surface flex items-center gap-3 p-5 text-sm">
                <Loader2 className="size-4 animate-spin text-teal" /> Re-fetching the live manifest in the sandbox and comparing hashes…
              </motion.div>
            ) : current ? (
              <motion.div key={`${current.ts}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
                <CheckDetail check={current} />
              </motion.div>
            ) : (
              <motion.div key="none" className="card-surface">
                <EmptyState icon={RefreshCw} title="Not verified yet" description="Click “Verify now” to compare the live manifest against this pin." />
              </motion.div>
            )}
          </AnimatePresence>
        </section>
      )}
    </>
  );
}
