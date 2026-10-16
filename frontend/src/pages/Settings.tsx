import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, KeyRound, Loader2, Save, Settings as SettingsIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Card, ErrorState, Mono, PageHeader, SkeletonRows } from "@/components/common";
import { EngineStatusPanel } from "@/components/EngineStatusPanel";
import { TechLogo } from "@/components/TechLogo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

const SANDBOX_MODES = [
  { value: "auto", label: "Auto", hint: "Docker if available, otherwise static extraction (never runs code on the host)" },
  { value: "docker", label: "Docker", hint: "Always use the hardened container" },
  { value: "static", label: "Static", hint: "Parse tool declarations from source, never execute" },
  { value: "host", label: "Host", hint: "Run on this machine. Only for code you trust." },
];

export default function Settings() {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings });
  const about = useQuery({ queryKey: ["about"], queryFn: api.about });
  const [form, setForm] = useState({ llm_base_url: "", llm_model: "", llm_api_key: "", promptguard_url: "", sandbox: "auto" });

  useEffect(() => {
    if (settings.data)
      setForm((f) => ({
        ...f,
        llm_base_url: settings.data.llm_base_url,
        llm_model: settings.data.llm_model,
        promptguard_url: settings.data.promptguard_url,
        sandbox: settings.data.sandbox,
      }));
  }, [settings.data]);

  const save = useMutation({
    mutationFn: () => api.saveSettings({ ...form, llm_api_key: form.llm_api_key || undefined }),
    onSuccess: (s) => {
      qc.setQueryData(["settings"], s);
      qc.invalidateQueries({ queryKey: ["health"] });
      qc.invalidateQueries({ queryKey: ["about"] });
      setForm((f) => ({ ...f, llm_api_key: "" }));
      toast.success("Settings saved", { description: "Applied to this server process (not persisted to disk)." });
    },
    onError: (e: Error) => toast.error("Could not save settings", { description: e.message }),
  });

  const field = (k: keyof typeof form) => ({
    value: form[k],
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value })),
  });

  return (
    <>
      <PageHeader
        icon={SettingsIcon}
        title="Settings & About"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Settings" }]}
        description="Configure the AI judge and the sandbox. Every AI layer is optional: when offline, MCPGuard falls back to rule-based detection."
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card title="Models" description="Exactly what runs during a scan">
            {about.isLoading ? (
              <SkeletonRows rows={2} />
            ) : about.isError ? (
              <ErrorState error={about.error} />
            ) : (
              <div className="grid gap-3 md:grid-cols-2">
                {about.data?.models.map((m) => (
                  <div key={m.role} className="rounded-xl border p-4">
                    <div className="flex items-center gap-2">
                      <span className="grid size-8 place-items-center rounded-lg bg-surface-2 ring-1 ring-inset ring-border">
                        <TechLogo id={m.role.startsWith("LLM") ? "llm" : "prompt_guard"} />
                      </span>
                      <div className="min-w-0">
                        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{m.role}</p>
                        <p className="truncate font-medium">{m.name}</p>
                      </div>
                    </div>
                    <dl className="mt-3 space-y-1 text-xs">
                      <div className="flex justify-between gap-2"><dt className="text-muted-foreground">Provider</dt><dd>{m.provider}</dd></div>
                      <div className="flex justify-between gap-2"><dt className="text-muted-foreground">Parameters</dt><dd className="font-mono">{m.parameters}</dd></div>
                      {m.endpoint && <div className="flex justify-between gap-2"><dt className="text-muted-foreground">Endpoint</dt><dd className="truncate font-mono">{m.endpoint}</dd></div>}
                      {m.model_id && <div className="flex justify-between gap-2"><dt className="text-muted-foreground">Model ID</dt><dd className="truncate font-mono">{m.model_id}</dd></div>}
                    </dl>
                    <div className="mt-3 flex flex-wrap gap-3 text-xs">
                      {m.license_url && <a className="inline-flex items-center gap-1 text-teal hover:underline" href={m.license_url} target="_blank" rel="noreferrer">License / terms <ExternalLink className="size-3" /></a>}
                      {m.card_url && <a className="inline-flex items-center gap-1 text-teal hover:underline" href={m.card_url} target="_blank" rel="noreferrer">Model card <ExternalLink className="size-3" /></a>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Configuration" description="Changes apply to the running server until restart. Use environment variables for permanent settings.">
            {settings.isLoading ? (
              <SkeletonRows rows={4} />
            ) : (
              <form
                className="space-y-5"
                onSubmit={(e) => {
                  e.preventDefault();
                  save.mutate();
                }}
              >
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="llm_base_url">LLM endpoint (OpenAI-compatible)</Label>
                    <Input id="llm_base_url" className="font-mono" {...field("llm_base_url")} />
                    <p className="text-[11px] text-muted-foreground">e.g. https://api.openai.com/v1 or http://localhost:11434/v1</p>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="llm_model">Model</Label>
                    <Input id="llm_model" className="font-mono" {...field("llm_model")} />
                    <p className="text-[11px] text-muted-foreground"><Mono>MCPGUARD_LLM_MODEL</Mono></p>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="llm_api_key" className="flex items-center gap-1.5"><KeyRound className="size-3.5" /> API key</Label>
                    <Input id="llm_api_key" type="password" autoComplete="off" placeholder={settings.data?.llm_api_key_set ? "•••••••• (set)" : "not set"} {...field("llm_api_key")} />
                    <p className="text-[11px] text-muted-foreground">Write-only, kept in memory. Prefer <Mono>OPENAI_API_KEY</Mono>.</p>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="promptguard_url">Prompt Guard 2 service URL</Label>
                    <Input id="promptguard_url" className="font-mono" placeholder="http://localhost:8001 (optional)" {...field("promptguard_url")} />
                    <p className="text-[11px] text-muted-foreground">Empty = in-process if transformers is installed</p>
                  </div>
                </div>
                <fieldset>
                  <legend className="mb-2 text-sm font-medium">Sandbox</legend>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {SANDBOX_MODES.map((m) => (
                      <label key={m.value} className="flex cursor-pointer items-start gap-3 rounded-lg border p-3 has-[:checked]:border-teal/50 has-[:checked]:bg-teal/5">
                        <input type="radio" name="sandbox" value={m.value} checked={form.sandbox === m.value} onChange={() => setForm((f) => ({ ...f, sandbox: m.value }))} className="mt-0.5 accent-[var(--teal)]" />
                        <span>
                          <span className="block text-sm font-medium">{m.label}</span>
                          <span className="block text-xs text-muted-foreground">{m.hint}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </fieldset>
                <div className="flex justify-end">
                  <Button type="submit" disabled={save.isPending}>
                    {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
                  </Button>
                </div>
              </form>
            )}
          </Card>

          <Card title="About">
            <p className="text-sm text-muted-foreground">
              MCPGuard {about.data?.version} · {about.data?.license} license. It audits MCP servers for tool poisoning, vulnerable code and rug pulls, using static analysis (Semgrep, Bandit, Gitleaks), an AI description analyzer and SHA-256 manifest pinning. Data is stored locally in SQLite at <Mono>{settings.data?.home}</Mono>.
            </p>
          </Card>
        </div>
        <EngineStatusPanel className="h-fit" />
      </div>
    </>
  );
}
