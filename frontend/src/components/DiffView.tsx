import { useMemo } from "react";
import { cn } from "@/lib/utils";

type Row = { kind: "same" | "del" | "add" | "mod"; left?: string; right?: string; ln?: number; rn?: number };

/** Classic LCS line diff, then pair adjacent delete/insert runs into side-by-side "modified" rows. */
function diffLines(a: string[], b: string[]): Row[] {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const ops: { t: "same" | "del" | "add"; l?: string; r?: string; i?: number; j?: number }[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) ops.push({ t: "same", l: a[i], r: b[j], i: i++, j: j++ });
    else if (dp[i + 1][j] >= dp[i][j + 1]) ops.push({ t: "del", l: a[i], i: i++ });
    else ops.push({ t: "add", r: b[j], j: j++ });
  }
  while (i < n) ops.push({ t: "del", l: a[i], i: i++ });
  while (j < m) ops.push({ t: "add", r: b[j], j: j++ });

  const rows: Row[] = [];
  for (let k = 0; k < ops.length; ) {
    if (ops[k].t === "same") {
      rows.push({ kind: "same", left: ops[k].l, right: ops[k].r, ln: ops[k].i! + 1, rn: ops[k].j! + 1 });
      k++;
      continue;
    }
    const dels: typeof ops = [];
    const adds: typeof ops = [];
    while (k < ops.length && ops[k].t !== "same") (ops[k].t === "del" ? dels : adds).push(ops[k++]);
    const len = Math.max(dels.length, adds.length);
    for (let x = 0; x < len; x++) {
      const d = dels[x];
      const ad = adds[x];
      rows.push({
        kind: d && ad ? "mod" : d ? "del" : "add",
        left: d?.l, right: ad?.r, ln: d ? d.i! + 1 : undefined, rn: ad ? ad.j! + 1 : undefined,
      });
    }
  }
  return rows;
}

/** Emphasize exactly the changed span of a modified line pair (common prefix/suffix trimmed). */
function inlineDiff(oldLine: string, newLine: string, side: "left" | "right") {
  let pre = 0;
  while (pre < oldLine.length && pre < newLine.length && oldLine[pre] === newLine[pre]) pre++;
  let suf = 0;
  while (
    suf < oldLine.length - pre &&
    suf < newLine.length - pre &&
    oldLine[oldLine.length - 1 - suf] === newLine[newLine.length - 1 - suf]
  )
    suf++;
  const line = side === "left" ? oldLine : newLine;
  const mid = line.slice(pre, line.length - suf);
  return (
    <>
      {line.slice(0, pre)}
      {mid && <span className={side === "left" ? "rounded-sm bg-danger/30" : "rounded-sm bg-success/30"}>{mid}</span>}
      {line.slice(line.length - suf)}
    </>
  );
}

/** Splits embedded "\n" in JSON strings onto their own lines so long descriptions stay readable. */
function prettyLines(text: string): string[] {
  return text ? text.replace(/\\n/g, "\n      ").split("\n") : [];
}

export function DiffView({ oldText, newText, oldLabel = "Pinned", newLabel = "Current" }: {
  oldText: string;
  newText: string;
  oldLabel?: string;
  newLabel?: string;
}) {
  const rows = useMemo(() => diffLines(prettyLines(oldText), prettyLines(newText)), [oldText, newText]);
  const stats = useMemo(
    () => ({
      del: rows.filter((r) => r.kind === "del" || r.kind === "mod").length,
      add: rows.filter((r) => r.kind === "add" || r.kind === "mod").length,
    }),
    [rows],
  );

  const cell = (text: string | undefined, kind: Row["kind"], side: "left" | "right", pair?: string) => {
    const changed = kind !== "same" && text !== undefined;
    const tone = !changed ? "" : side === "left" ? "bg-danger/10 text-red-700 dark:text-red-200" : "bg-success/10 text-green-700 dark:text-green-200";
    return (
      <td className={cn("whitespace-pre-wrap break-all px-3 py-0.5 align-top", tone, text === undefined && kind !== "same" && "bg-muted/30")}>
        {changed && <span className="mr-1.5 select-none opacity-60">{side === "left" ? "−" : "+"}</span>}
        {kind === "mod" && text !== undefined && pair !== undefined
          ? inlineDiff(side === "left" ? text : pair, side === "left" ? pair : text, side)
          : text}
      </td>
    );
  };

  return (
    <div className="overflow-hidden rounded-lg border">
      <div className="grid grid-cols-2 border-b bg-muted/50 text-xs font-medium">
        <div className="flex items-center justify-between border-r px-3 py-2">
          <span>{oldLabel}</span>
          <span className="font-mono text-danger">−{stats.del}</span>
        </div>
        <div className="flex items-center justify-between px-3 py-2">
          <span>{newLabel}</span>
          <span className="font-mono text-success">+{stats.add}</span>
        </div>
      </div>
      <div className="max-h-[480px] overflow-auto scrollbar-thin">
        <table className="w-full table-fixed border-collapse font-mono text-[12px] leading-relaxed">
          <colgroup>
            <col className="w-10" />
            <col />
            <col className="w-10" />
            <col />
          </colgroup>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-b border-border/40 last:border-0">
                <td className="select-none border-r bg-muted/30 px-2 text-right text-muted-foreground/70">{r.ln ?? ""}</td>
                {cell(r.left, r.kind, "left", r.right)}
                <td className="select-none border-x bg-muted/30 px-2 text-right text-muted-foreground/70">{r.rn ?? ""}</td>
                {cell(r.right, r.kind, "right", r.left)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
