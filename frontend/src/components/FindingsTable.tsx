import { ArrowDown, ArrowUp, ArrowUpDown, Search, ShieldCheck, X } from "lucide-react";
import { useMemo, useState } from "react";
import { EmptyState } from "@/components/common";
import { ConfidenceBar } from "@/components/FindingDrawer";
import { SeverityBadge } from "@/components/severity";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { CATEGORY_LABEL, SOURCE_LABEL } from "@/lib/format";
import { cn } from "@/lib/utils";
import { SEVERITIES, type Category, type Finding, type Severity, type Source } from "@/lib/types";

type SortKey = "severity" | "category" | "source" | "tool" | "confidence";
const SEV_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const ALL = "__all";

function FilterSelect({ label, value, onChange, options }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(String(v ?? ALL))}>
      <SelectTrigger size="sm" className="min-w-36" aria-label={`Filter by ${label}`}>
        <SelectValue>{(v: string) => (v === ALL ? `All ${label}` : options.find((o) => o.value === v)?.label ?? v)}</SelectValue>
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>All {label}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function FindingsTable({ findings, onSelect, initialTool }: { findings: Finding[]; onSelect: (f: Finding) => void; initialTool?: string }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState(ALL);
  const [cat, setCat] = useState(ALL);
  const [src, setSrc] = useState(ALL);
  const [tool, setTool] = useState(initialTool ?? ALL);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "severity", dir: -1 });

  const tools = useMemo(() => [...new Set(findings.map((f) => f.tool).filter(Boolean) as string[])].sort(), [findings]);
  const categories = useMemo(() => [...new Set(findings.map((f) => f.category))], [findings]);
  const sources = useMemo(() => [...new Set(findings.map((f) => f.source))], [findings]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const filtered = findings.filter(
      (f) =>
        (sev === ALL || f.severity === sev) &&
        (cat === ALL || f.category === cat) &&
        (src === ALL || f.source === src) &&
        (tool === ALL || f.tool === tool) &&
        (!needle || `${f.id} ${f.title} ${f.evidence} ${f.tool ?? ""} ${f.file ?? ""}`.toLowerCase().includes(needle)),
    );
    const val = (f: Finding): string | number =>
      sort.key === "severity" ? SEV_RANK[f.severity] * 10 + f.confidence : sort.key === "confidence" ? f.confidence : (f[sort.key] ?? "") as string;
    return [...filtered].sort((a, b) => (val(a) > val(b) ? 1 : val(a) < val(b) ? -1 : 0) * sort.dir);
  }, [findings, q, sev, cat, src, tool, sort]);

  const active = q || sev !== ALL || cat !== ALL || src !== ALL || tool !== ALL;
  const clear = () => {
    setQ("");
    setSev(ALL);
    setCat(ALL);
    setSrc(ALL);
    setTool(ALL);
  };

  const Header = ({ k, children, className }: { k: SortKey; children: React.ReactNode; className?: string }) => {
    const activeSort = sort.key === k;
    const Icon = !activeSort ? ArrowUpDown : sort.dir === -1 ? ArrowDown : ArrowUp;
    return (
      <th className={cn("px-3 py-2.5 text-left font-medium", className)} aria-sort={activeSort ? (sort.dir === -1 ? "descending" : "ascending") : "none"}>
        <button
          className="inline-flex items-center gap-1 rounded hover:text-foreground focus-visible:outline-2"
          onClick={() => setSort((s) => ({ key: k, dir: s.key === k ? (s.dir === 1 ? -1 : 1) : -1 }))}
        >
          {children}
          <Icon className={cn("size-3", !activeSort && "opacity-40")} aria-hidden />
        </button>
      </th>
    );
  };

  if (!findings.length) {
    return (
      <EmptyState icon={ShieldCheck} title="No findings" description="None of the enabled modules found anything worth reporting for this server." />
    );
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
        <div className="relative min-w-48 flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search findings, evidence, files…" className="h-7 pl-8 text-sm" aria-label="Search findings" />
        </div>
        <FilterSelect label="severities" value={sev} onChange={setSev} options={SEVERITIES.map((s) => ({ value: s, label: s }))} />
        <FilterSelect label="categories" value={cat} onChange={setCat} options={categories.map((c) => ({ value: c, label: CATEGORY_LABEL[c as Category] }))} />
        <FilterSelect label="modules" value={src} onChange={setSrc} options={sources.map((s) => ({ value: s, label: SOURCE_LABEL[s as Source] }))} />
        {tools.length > 0 && <FilterSelect label="tools" value={tool} onChange={setTool} options={tools.map((t) => ({ value: t, label: t }))} />}
        {active && (
          <Button variant="ghost" size="sm" onClick={clear}>
            <X /> Clear
          </Button>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
            <tr>
              <Header k="severity" className="w-32">Severity</Header>
              <th className="px-3 py-2.5 text-left font-medium">Finding</th>
              <Header k="category">Category</Header>
              <Header k="source">Module</Header>
              <Header k="tool">Tool</Header>
              <Header k="confidence" className="w-36">Confidence</Header>
            </tr>
          </thead>
          <tbody className="divide-y">
            {rows.map((f) => (
              <tr
                key={f.id}
                tabIndex={0}
                onClick={() => onSelect(f)}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onSelect(f))}
                className="cursor-pointer transition-colors hover:bg-muted/40 focus-visible:bg-muted/50 focus-visible:outline-none"
              >
                <td className="px-3 py-3 align-top">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="max-w-md px-3 py-3 align-top">
                  <div className="font-medium leading-snug">{f.title}</div>
                  <div className="mt-0.5 flex flex-wrap gap-x-2 font-mono text-[11px] text-muted-foreground">
                    <span>{f.id}</span>
                    {f.file && <span className="truncate">{f.file}{f.line ? `:${f.line}` : ""}</span>}
                  </div>
                </td>
                <td className="whitespace-nowrap px-3 py-3 align-top text-muted-foreground">{CATEGORY_LABEL[f.category]}</td>
                <td className="whitespace-nowrap px-3 py-3 align-top text-muted-foreground">{SOURCE_LABEL[f.source]}</td>
                <td className="px-3 py-3 align-top">{f.tool ? <code className="font-mono text-xs">{f.tool}</code> : <span className="text-muted-foreground">—</span>}</td>
                <td className="px-3 py-3 align-top">
                  <ConfidenceBar value={f.confidence} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="px-4 py-10 text-center text-sm text-muted-foreground">No findings match these filters.</p>}
      </div>
    </div>
  );
}
