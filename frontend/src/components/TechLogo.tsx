// Brand marks for the engine panel. Logos come from simple-icons (CC0) where available;
// engines without a published mark use a neutral lucide glyph.
import { Bot, Database, KeyRound, ScanSearch, ShieldCheck, Sparkles, type LucideIcon } from "lucide-react";
import { siDocker, siMeta, siOllama, siPython, siSqlite, type SimpleIcon } from "simple-icons";
import { cn } from "@/lib/utils";

const BRAND: Record<string, SimpleIcon> = {
  docker: siDocker,
  prompt_guard: siMeta,
  python: siPython,
  sqlite: siSqlite,
  ollama: siOllama,
};
// Marks whose brand color is near-black would disappear on the navy theme.
const COLOR_OVERRIDE: Record<string, string> = { sqlite: "#3FA9DC", ollama: "currentColor" };
const GLYPH: Record<string, LucideIcon> = {
  llm: Sparkles,
  semgrep: ScanSearch,
  gitleaks: KeyRound,
  bandit: ShieldCheck,
  builtin: Bot,
  storage: Database,
};

export function TechLogo({ id, className }: { id: string; className?: string }) {
  const brand = BRAND[id];
  if (brand) {
    return (
      <svg role="img" viewBox="0 0 24 24" className={cn("size-4", className)} fill={COLOR_OVERRIDE[id] ?? `#${brand.hex}`} aria-label={brand.title}>
        <path d={brand.path} />
      </svg>
    );
  }
  const Glyph = GLYPH[id] ?? Bot;
  return <Glyph className={cn("size-4", className)} aria-hidden />;
}
