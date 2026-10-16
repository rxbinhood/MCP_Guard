import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode, lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";
import { AppShell } from "@/components/AppShell";
import { EmptyState, SkeletonRows } from "@/components/common";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider, useTheme } from "@/lib/theme";
import Dashboard from "@/pages/Dashboard";
import "./index.css";
import { Compass } from "lucide-react";

const NewScan = lazy(() => import("@/pages/NewScan"));
const Scans = lazy(() => import("@/pages/Scans"));
const ScanResult = lazy(() => import("@/pages/ScanResult"));
const ToolsInspector = lazy(() => import("@/pages/ToolsInspector"));
const PinDiff = lazy(() => import("@/pages/PinDiff"));
const Evaluation = lazy(() => import("@/pages/Evaluation"));
const Settings = lazy(() => import("@/pages/Settings"));

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 5_000 } },
});

function ThemedToaster() {
  const { theme } = useTheme();
  return <Toaster theme={theme} position="bottom-right" richColors closeButton />;
}

function NotFound() {
  return <EmptyState icon={Compass} title="Page not found" description="That page doesn't exist. Use the sidebar or press ⌘K to jump somewhere." />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delay={250}>
          <BrowserRouter>
            <Suspense fallback={<SkeletonRows rows={6} className="p-8" />}>
              <Routes>
                <Route element={<AppShell />}>
                  <Route index element={<Dashboard />} />
                  <Route path="scan/new" element={<NewScan />} />
                  <Route path="scans" element={<Scans />} />
                  <Route path="scans/:id" element={<ScanResult />} />
                  <Route path="tools" element={<ToolsInspector />} />
                  <Route path="pins" element={<PinDiff />} />
                  <Route path="evaluation" element={<Evaluation />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="*" element={<NotFound />} />
                </Route>
              </Routes>
            </Suspense>
          </BrowserRouter>
          <ThemedToaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
);
