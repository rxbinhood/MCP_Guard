import { Fragment, useMemo } from "react";
import { cn } from "@/lib/utils";

// Invisible / direction-override characters are rendered as visible tokens so hidden
// payloads are obvious to the reviewer.
const INVISIBLE = /[​-‏⁠-⁤﻿‪-‮⁦-⁩]|[\u{E0000}-\u{E007F}]/gu;

function revealInvisible(text: string): (string | { hidden: string })[] {
  const out: (string | { hidden: string })[] = [];
  let last = 0;
  for (const m of text.matchAll(INVISIBLE)) {
    const i = m.index ?? 0;
    if (i > last) out.push(text.slice(last, i));
    const cp = m[0].codePointAt(0)!;
    out.push({ hidden: cp >= 0xe0000 ? String.fromCodePoint(cp - 0xe0000) : `U+${cp.toString(16).toUpperCase().padStart(4, "0")}` });
    last = i + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function escapeRegExp(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Renders text with every occurrence of `highlights` marked (case-insensitive), and
 * invisible Unicode made visible. Used for evidence blocks and tool descriptions.
 */
export function HighlightedText({ text, highlights = [], className, mono = true }: {
  text: string;
  highlights?: string[];
  className?: string;
  mono?: boolean;
}) {
  const parts = useMemo(() => {
    const terms = [...new Set(highlights.map((h) => h.trim()).filter((h) => h.length >= 2))].sort((a, b) => b.length - a.length);
    if (!terms.length) return [{ text, hit: false }];
    const re = new RegExp(`(${terms.map(escapeRegExp).join("|")})`, "gi");
    return text.split(re).filter(Boolean).map((t) => ({ text: t, hit: terms.some((term) => term.toLowerCase() === t.toLowerCase()) }));
  }, [text, highlights]);

  return (
    <span className={cn(mono && "font-mono", "whitespace-pre-wrap break-words", className)}>
      {parts.map((p, i) => {
        const pieces = revealInvisible(p.text).map((piece, j) =>
          typeof piece === "string" ? (
            <Fragment key={j}>{piece}</Fragment>
          ) : (
            <span key={j} title="Invisible character" className="mx-px rounded bg-indigo/20 px-1 text-[0.85em] text-indigo ring-1 ring-inset ring-indigo/40">
              {piece.hidden}
            </span>
          ),
        );
        return p.hit ? (
          <mark key={i} className="rounded-sm bg-danger/20 px-0.5 text-danger ring-1 ring-inset ring-danger/40 dark:text-red-300">
            {pieces}
          </mark>
        ) : (
          <Fragment key={i}>{pieces}</Fragment>
        );
      })}
    </span>
  );
}
