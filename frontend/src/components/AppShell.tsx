import { AnimatePresence, motion } from "framer-motion";
import {
  BarChart3,
  Boxes,
  FlaskConical,
  GitCompareArrows,
  LayoutDashboard,
  ListChecks,
  Menu,
  Moon,
  Plus,
  Search,
  Settings,
  Sparkles,
  Sun,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { Kbd } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { targetName } from "@/lib/format";
import { useHealth, useScans } from "@/lib/hooks";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

const NAV: { to: string; label: string; icon: LucideIcon; end?: boolean }[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/scan/new", label: "New scan", icon: Plus },
  { to: "/scans", label: "Scans", icon: ListChecks },
  { to: "/tools", label: "Tools inspector", icon: Boxes },
  { to: "/pins", label: "Pin & Diff", icon: GitCompareArrows },
  { to: "/evaluation", label: "Evaluation", icon: FlaskConical },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <defs>
        <linearGradient id="mg" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stopColor="#14B8A6" />
          <stop offset="1" stopColor="#6366F1" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 4.5 7v8.2c0 7 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.3 11.5-14.3V7L16 2.5Z" fill="url(#mg)" />
      <path d="M11 15.5h10M11 15.5l3-3M11 15.5l3 3M21 15.5l-3-3M21 15.5l-3 3" stroke="#04201D" strokeWidth="2" strokeLinecap="round" fill="none" opacity=".85" />
    </svg>
  );
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const { data: health } = useHealth();
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <Logo className="size-8" />
        <div>
          <p className="text-[15px] font-semibold leading-none tracking-tight">MCPGuard</p>
          <p className="mt-1 text-[11px] text-muted-foreground">MCP server security</p>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 px-3" aria-label="Main">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                "group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-ring",
                isActive ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive && <motion.span layoutId="nav-indicator" className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-teal" />}
                <Icon className={cn("size-4", isActive && "text-teal")} aria-hidden />
                {label}
              </>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="m-3 rounded-xl border bg-card/60 p-3.5">
        <div className="flex items-center gap-2 text-xs font-medium">
          <Sparkles className="size-3.5 text-indigo" aria-hidden /> AI analysis
        </div>
        {health ? (
          <p className={cn("mt-1 text-xs", health.ai_online ? "text-success" : "text-warning")}>
            {health.ai_online ? "LLM judge online" : "AI model offline · rule-based fallback"}
          </p>
        ) : (
          <p className="mt-1 text-xs text-muted-foreground">Checking…</p>
        )}
        <p className="mt-2 font-mono text-[10px] text-muted-foreground">v{health?.version ?? "…"}</p>
      </div>
    </div>
  );
}

function CommandPalette({ open, setOpen }: { open: boolean; setOpen: (o: boolean) => void }) {
  const navigate = useNavigate();
  const { theme, toggle } = useTheme();
  const { data: scans } = useScans(20);
  const go = (to: string) => {
    setOpen(false);
    navigate(to);
  };
  return (
    <CommandDialog open={open} onOpenChange={setOpen} title="Quick actions" description="Jump to a page or a recent scan">
      <Command>
        <CommandInput placeholder="Type a command or search scans…" />
        <CommandList>
          <CommandEmpty>No results.</CommandEmpty>
          <CommandGroup heading="Actions">
            <CommandItem onSelect={() => go("/scan/new")}><Plus /> New scan</CommandItem>
            <CommandItem onSelect={() => go("/pins")}><GitCompareArrows /> Verify pinned servers</CommandItem>
            <CommandItem onSelect={() => go("/evaluation")}><BarChart3 /> View evaluation</CommandItem>
            <CommandItem onSelect={() => { toggle(); setOpen(false); }}>
              {theme === "dark" ? <Sun /> : <Moon />} Switch to {theme === "dark" ? "light" : "dark"} theme
            </CommandItem>
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="Pages">
            {NAV.map((n) => (
              <CommandItem key={n.to} onSelect={() => go(n.to)}>
                <n.icon /> {n.label}
              </CommandItem>
            ))}
          </CommandGroup>
          {!!scans?.length && (
            <>
              <CommandSeparator />
              <CommandGroup heading="Recent scans">
                {scans.slice(0, 8).map((s) => (
                  <CommandItem key={s.id} value={`${s.server_name ?? ""} ${s.target} ${s.id}`} onSelect={() => go(`/scans/${s.id}`)}>
                    <ListChecks /> {s.server_name || targetName(s.target)}
                    <span className="ml-auto font-mono text-[10px] text-muted-foreground">{s.verdict ?? s.status}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}
        </CommandList>
      </Command>
    </CommandDialog>
  );
}

export function AppShell() {
  const { theme, toggle } = useTheme();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const { data: health } = useHealth();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="flex min-h-screen bg-background">
      <a href="#main" className="sr-only z-50 rounded bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-3 focus:top-3">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-sidebar-border bg-sidebar lg:block">
        <SidebarContent />
      </aside>
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="w-72 bg-sidebar p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarContent onNavigate={() => setMobileOpen(false)} />
        </SheetContent>
      </Sheet>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur-md md:px-8">
          <Button variant="ghost" size="icon-sm" className="lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation">
            <Menu />
          </Button>
          <button
            onClick={() => setPaletteOpen(true)}
            className="flex h-8 w-full max-w-sm items-center gap-2 rounded-lg border bg-card/60 px-3 text-sm text-muted-foreground transition-colors hover:bg-card focus-visible:outline-2 focus-visible:outline-ring"
          >
            <Search className="size-3.5" aria-hidden />
            <span className="flex-1 text-left">Search or jump to…</span>
            <Kbd>⌘K</Kbd>
          </button>
          <div className="ml-auto flex items-center gap-2">
            {health && !health.ai_online && (
              <Tooltip>
                <TooltipTrigger
                  render={
                    <NavLink to="/settings" className="hidden items-center gap-1.5 rounded-full bg-warning/12 px-2.5 py-1 text-xs font-medium text-warning ring-1 ring-inset ring-warning/30 sm:flex" />
                  }
                >
                  <span className="size-1.5 rounded-full bg-warning" aria-hidden /> AI model offline
                </TooltipTrigger>
                <TooltipContent>No LLM judge reachable. Using rule-based detection; configure it in Settings.</TooltipContent>
              </Tooltip>
            )}
            <Button variant="ghost" size="icon-sm" onClick={toggle} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
              {theme === "dark" ? <Sun /> : <Moon />}
            </Button>
            <Button size="sm" className="hidden sm:inline-flex" nativeButton={false} render={<NavLink to="/scan/new" />}>
              <Plus /> New scan
            </Button>
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 md:px-8 md:py-8">
          <AnimatePresence mode="wait">
            <motion.div key={location.pathname} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
      <CommandPalette open={paletteOpen} setOpen={setPaletteOpen} />
    </div>
  );
}
