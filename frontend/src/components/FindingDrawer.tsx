import { BookOpen, Check, Copy, FileCode2, Fingerprint, Lightbulb, Wrench } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { HighlightedText } from "@/components/HighlightedText";
import { SeverityBadge } from "@/components/severity";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { CATEGORY_LABEL, SOURCE_LABEL } from "@/lib/format";
import type { Finding } from "@/lib/types";

const OWASP_URL = "https://genai.owasp.org/llm-top-10/";

function Section({ icon: Icon, title, children }: { icon: typeof Lightbulb; title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        <Icon className="size-3.5" aria-hidden /> {title}
      </h3>
      {children}
    </section>
  );
}

export function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  return (
    <div className="flex items-center gap-2" aria-label={`Confidence ${pct}%`}>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full bg-teal" style={{ width: `${pct}%` }} />
      </div>
      <span className="w-9 text-right font-mono text-xs tabular-nums text-muted-foreground">{pct}%</span>
    </div>
  );
}

export function FindingDrawer({ finding, onOpenChange }: { finding: Finding | null; onOpenChange: (open: boolean) => void }) {
  const [copied, setCopied] = useState(false);
  const copyFix = async () => {
    if (!finding) return;
    try {
      await navigator.clipboard.writeText(finding.fix);
      setCopied(true);
      toast.success("Fix copied to clipboard");
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Clipboard unavailable in this browser context");
    }
  };

  return (
    <Sheet open={!!finding} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full gap-0 overflow-y-auto p-0 scrollbar-thin sm:max-w-xl">
        {finding && (
          <>
            <SheetHeader className="border-b px-6 py-5 pr-12">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="font-mono text-xs text-muted-foreground">{finding.id}</span>
              </div>
              <SheetTitle className="text-base leading-snug">{finding.title}</SheetTitle>
              <SheetDescription className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
                <span>{CATEGORY_LABEL[finding.category]}</span>
                <span aria-hidden>·</span>
                <span>{SOURCE_LABEL[finding.source]}</span>
                {finding.tool && (
                  <>
                    <span aria-hidden>·</span>
                    <span>
                      tool <code className="font-mono text-foreground">{finding.tool}</code>
                    </span>
                  </>
                )}
              </SheetDescription>
            </SheetHeader>

            <div className="space-y-6 px-6 py-5">
              <Section icon={FileCode2} title="Evidence">
                {finding.file && (
                  <p className="mb-1.5 font-mono text-xs text-muted-foreground">
                    {finding.file}
                    {finding.line ? `:${finding.line}` : ""}
                  </p>
                )}
                <pre className="max-h-80 overflow-auto rounded-lg border bg-background p-3.5 text-[12.5px] leading-relaxed scrollbar-thin">
                  <HighlightedText text={finding.evidence || "(no snippet)"} highlights={finding.highlights} />
                </pre>
              </Section>

              {finding.why && (
                <Section icon={Lightbulb} title="Why it matters">
                  <p className="text-sm leading-relaxed text-foreground/90">{finding.why}</p>
                </Section>
              )}

              <Section icon={Wrench} title="Fix">
                <div className="relative rounded-lg border border-teal/30 bg-teal/5 p-3.5 pr-12">
                  <p className="text-sm leading-relaxed">{finding.fix || "No automated fix available."}</p>
                  {finding.fix && (
                    <Button variant="ghost" size="icon-sm" className="absolute right-2 top-2" onClick={copyFix} aria-label="Copy fix">
                      {copied ? <Check className="text-success" /> : <Copy />}
                    </Button>
                  )}
                </div>
              </Section>

              <div className="grid gap-5 sm:grid-cols-2">
                <Section icon={Fingerprint} title="Confidence">
                  <ConfidenceBar value={finding.confidence} />
                  {finding.detectors.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {finding.detectors.map((d) => (
                        <span key={d} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                          {d}
                        </span>
                      ))}
                    </div>
                  )}
                </Section>
                <Section icon={BookOpen} title="Reference">
                  {finding.owasp_llm_ref ? (
                    <a href={OWASP_URL} target="_blank" rel="noreferrer" className="text-sm text-teal underline-offset-4 hover:underline">
                      OWASP {finding.owasp_llm_ref}
                    </a>
                  ) : (
                    <span className="text-sm text-muted-foreground">—</span>
                  )}
                  {typeof finding.extra?.cwe === "string" && <p className="mt-1 text-xs text-muted-foreground">{finding.extra.cwe}</p>}
                  {finding.rule_id && <p className="mt-1 font-mono text-[11px] text-muted-foreground">{finding.rule_id}</p>}
                </Section>
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
