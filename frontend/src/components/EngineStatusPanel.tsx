import { useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { useState } from "react";
import { Card, SkeletonRows } from "@/components/common";
import { HealthPill } from "@/components/severity";
import { TechLogo } from "@/components/TechLogo";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import { useHealth } from "@/lib/hooks";

const KIND_LABEL: Record<string, string> = { ai: "AI models", sandbox: "Sandbox", static: "Static analysis", storage: "Storage" };

export function EngineStatusPanel({ className }: { className?: string }) {
  const { data, isLoading } = useHealth();
  const qc = useQueryClient();
  const [refreshing, setRefreshing] = useState(false);

  const refresh = async () => {
    setRefreshing(true);
    try {
      qc.setQueryData(["health"], await api.health(true));
    } finally {
      setRefreshing(false);
    }
  };

  const groups = ["ai", "sandbox", "static", "storage"];
  return (
    <Card
      className={className}
      title="Engine status"
      description="Optional engines degrade gracefully when offline"
      action={
        <Button variant="ghost" size="icon-sm" onClick={refresh} aria-label="Re-check engines" disabled={refreshing}>
          <RefreshCw className={refreshing ? "animate-spin" : ""} />
        </Button>
      }
      bodyClassName="p-0"
    >
      {isLoading || !data ? (
        <SkeletonRows rows={6} className="p-5" />
      ) : (
        <div className="divide-y">
          {groups.map((g) => {
            const items = data.engines.filter((e) => e.kind === g);
            if (!items.length) return null;
            return (
              <div key={g} className="px-5 py-3">
                <p className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{KIND_LABEL[g]}</p>
                <ul className="space-y-2">
                  {items.map((e) => (
                    <li key={e.id} className="flex items-center justify-between gap-3">
                      <Tooltip>
                        <TooltipTrigger className="flex min-w-0 items-center gap-2.5 text-left">
                          <span className="grid size-7 shrink-0 place-items-center rounded-md bg-surface-2 ring-1 ring-inset ring-border">
                            <TechLogo id={e.id} />
                          </span>
                          <span className="min-w-0">
                            <span className="block truncate text-sm font-medium">{e.label}</span>
                            {e.model && <span className="block truncate font-mono text-[11px] text-muted-foreground">{e.model}</span>}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">{e.detail}</TooltipContent>
                      </Tooltip>
                      <HealthPill ok={e.ok} />
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}
