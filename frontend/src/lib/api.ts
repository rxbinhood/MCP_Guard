// Thin typed client for the MCPGuard REST API. All paths are relative (/api/...) so the
// same build works behind the Vite dev proxy and when served by FastAPI.
import type {
  About,
  EvalResponse,
  Finding,
  Health,
  PinDetail,
  PinSummary,
  ScanDetail,
  ScanSummary,
  Settings,
  Stats,
  VerifyResult,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError(0, "Cannot reach the MCPGuard API. Is `mcpguard serve` running?");
  }
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });

export interface ScanRequest {
  target: string;
  static: boolean;
  ai: boolean;
  dynamic: boolean;
  sandbox?: string | null;
}

export const api = {
  health: (refresh = false) => request<Health>(`/api/health${refresh ? "?refresh=true" : ""}`),
  stats: () => request<Stats>("/api/stats"),
  scans: (limit = 50) => request<ScanSummary[]>(`/api/scans?limit=${limit}`),
  scan: (id: string) => request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),
  findings: (id: string) => request<Finding[]>(`/api/scans/${encodeURIComponent(id)}/findings`),
  createScan: (body: ScanRequest) => request<{ id: string; status: string }>("/api/scans", json(body)),
  deleteScan: (id: string) => request<void>(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
  reportUrl: (id: string, format: "md" | "json" | "sarif") =>
    `/api/scans/${encodeURIComponent(id)}/report?format=${format}`,
  eventsUrl: (id: string) => `/api/scans/${encodeURIComponent(id)}/events`,

  pins: () => request<PinSummary[]>("/api/pins"),
  pin: (target: string) => request<PinSummary>("/api/pins", json({ target })),
  pinDetail: (key: string) => request<PinDetail>(`/api/pins/detail?server_key=${encodeURIComponent(key)}`),
  verify: (key: string, ai = true) => request<VerifyResult>("/api/pins/verify", json({ server_key: key, ai })),
  unpin: (key: string) => request<void>(`/api/pins?server_key=${encodeURIComponent(key)}`, { method: "DELETE" }),

  rugpull: () => request<{ armed: boolean; target: string; server_key: string }>("/api/demo/rugpull"),
  setRugpull: (armed: boolean) =>
    request<{ armed: boolean; target: string; server_key: string }>("/api/demo/rugpull", json({ armed })),

  eval: () => request<EvalResponse>("/api/eval"),
  runEval: (ai = true) => request<EvalResponse>(`/api/eval?ai=${ai}`, { method: "POST" }),

  settings: () => request<Settings>("/api/settings"),
  saveSettings: (body: Partial<Settings> & { llm_api_key?: string }) =>
    request<Settings>("/api/settings", { method: "PUT", body: JSON.stringify(body) }),
  about: () => request<About>("/api/about"),
};
