// Dashboard charts. Severity colors come from the validated --sev-* tokens; every chart has
// a legend with icons + counts (identity never relies on color alone) and a hover tooltip.
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITY_META } from "@/components/severity";
import { SEVERITIES, type Counts, type Severity } from "@/lib/types";

const AXIS = { fontSize: 11, fill: "var(--muted-foreground)" };

interface TipPayload {
  name?: string;
  value?: number;
  dataKey?: string | number;
  payload?: Record<string, unknown>;
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: TipPayload[]; label?: string }) {
  if (!active || !payload?.length) return null;
  const rows = payload.filter((p) => (p.value ?? 0) > 0);
  return (
    <div className="min-w-36 rounded-lg border bg-popover px-3 py-2 text-xs shadow-lg">
      {label && <p className="mb-1.5 font-medium">{label}</p>}
      {(rows.length ? rows : payload).map((p) => {
        const sev = String(p.dataKey ?? p.name) as Severity;
        const meta = SEVERITY_META[sev];
        return (
          <div key={sev} className="flex items-center justify-between gap-4 py-0.5">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className="size-2 rounded-sm" style={{ background: meta?.hex }} aria-hidden />
              {sev}
            </span>
            <span className="font-mono tabular-nums text-foreground">{p.value}</span>
          </div>
        );
      })}
    </div>
  );
}

export function SeverityLegend({ counts, total }: { counts: Counts; total?: number }) {
  return (
    <ul className="space-y-1.5">
      {SEVERITIES.map((s) => {
        const m = SEVERITY_META[s];
        const Icon = m.icon;
        const n = counts[s] ?? 0;
        return (
          <li key={s} className="flex items-center justify-between gap-3 text-sm">
            <span className="flex items-center gap-2">
              <span className="size-2.5 rounded-sm" style={{ background: m.hex }} aria-hidden />
              <Icon className={`size-3.5 ${m.text}`} aria-hidden />
              <span className="text-foreground/90">{s.charAt(0) + s.slice(1).toLowerCase()}</span>
            </span>
            <span className="font-mono text-sm tabular-nums">
              {n}
              {total ? <span className="ml-1.5 text-xs text-muted-foreground">{Math.round((n / total) * 100)}%</span> : null}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

export function SeverityDonut({ counts }: { counts: Counts }) {
  const data = SEVERITIES.map((s) => ({ name: s, value: counts[s] ?? 0 })).filter((d) => d.value > 0);
  const total = data.reduce((a, b) => a + b.value, 0);
  return (
    <div className="flex flex-col items-center gap-6 sm:flex-row">
      <div className="relative size-44 shrink-0" role="img" aria-label={`Findings by severity: ${data.map((d) => `${d.value} ${d.name}`).join(", ") || "none"}`}>
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={data.length ? data : [{ name: "none", value: 1 }]}
              dataKey="value"
              innerRadius="68%"
              outerRadius="100%"
              stroke="var(--card)"
              strokeWidth={2}
              startAngle={90}
              endAngle={-270}
              isAnimationActive
            >
              {(data.length ? data : [{ name: "none" }]).map((d) => (
                <Cell key={d.name} fill={d.name === "none" ? "var(--muted)" : SEVERITY_META[d.name as Severity].hex} />
              ))}
            </Pie>
            {data.length > 0 && <Tooltip content={<ChartTooltip />} />}
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-2xl font-semibold tabular-nums">{total}</div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">findings</div>
          </div>
        </div>
      </div>
      <div className="w-full">
        <SeverityLegend counts={counts} total={total} />
      </div>
    </div>
  );
}

/** Stacked bars by severity. `rows` = [{ label, CRITICAL, HIGH, ... }]. */
export function SeverityStackedBars({ rows, height = 220 }: { rows: ({ label: string } & Partial<Counts>)[]; height?: number }) {
  const present = SEVERITIES.filter((s) => rows.some((r) => (r[s] ?? 0) > 0));
  const series = present.length ? present : (["HIGH"] as Severity[]);
  return (
    <div style={{ height }}>
      <ResponsiveContainer>
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -20 }} barCategoryGap="28%">
          <CartesianGrid vertical={false} stroke="var(--border)" strokeOpacity={0.6} />
          <XAxis dataKey="label" tick={AXIS} tickLine={false} axisLine={false} interval={0} />
          <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--muted)", opacity: 0.5 }} />
          {[...series].reverse().map((s, i, arr) => (
            <Bar
              key={s}
              dataKey={s}
              stackId="sev"
              fill={SEVERITY_META[s].hex}
              stroke="var(--card)"
              strokeWidth={2}
              radius={i === arr.length - 1 ? [4, 4, 0, 0] : 0}
              maxBarSize={36}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
