import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { ScanEvent } from "./types";

export const useHealth = () =>
  useQuery({ queryKey: ["health"], queryFn: () => api.health(), refetchInterval: 30_000 });
export const useStats = () => useQuery({ queryKey: ["stats"], queryFn: api.stats });
export const useScans = (limit = 50) =>
  useQuery({ queryKey: ["scans", limit], queryFn: () => api.scans(limit), refetchInterval: 15_000 });
export const useScan = (id?: string) =>
  useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.scan(id!),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data && ["queued", "running"].includes(q.state.data.status) ? 1500 : false),
  });
export const usePins = () => useQuery({ queryKey: ["pins"], queryFn: api.pins });

/**
 * Subscribe to a scan's Server-Sent Events stream. Events are replayed from the start,
 * so this also works when opening a scan that is already running or finished.
 */
export function useScanEvents(scanId?: string) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [done, setDone] = useState(false);
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setEvents([]);
    setDone(false);
    const es = new EventSource(api.eventsUrl(scanId));
    sourceRef.current = es;
    const push = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as ScanEvent;
        setEvents((prev) => (data.seq && prev.some((p) => p.seq === data.seq) ? prev : [...prev, data]));
      } catch {
        /* ignore malformed */
      }
    };
    es.onopen = () => setConnected(true);
    es.addEventListener("module", push);
    es.addEventListener("log", push);
    es.addEventListener("scan", push);
    es.addEventListener("end", () => {
      setDone(true);
      es.close();
    });
    es.onerror = () => setConnected(false);
    return () => es.close();
  }, [scanId]);

  return { events, done, connected };
}
