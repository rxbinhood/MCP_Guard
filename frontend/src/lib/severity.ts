// Display metadata for severities and verdicts (icon + color tokens + copy).
import {
  AlertOctagon,
  AlertTriangle,
  CircleDot,
  Info,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  type LucideIcon,
} from "lucide-react";
import type { Severity, Verdict } from "./types";

export const SEVERITY_META: Record<Severity, { icon: LucideIcon; text: string; bg: string; ring: string; hex: string }> = {
  CRITICAL: { icon: AlertOctagon, text: "text-sev-critical-fg", bg: "bg-sev-critical/12", ring: "ring-sev-critical/30", hex: "var(--sev-critical)" },
  HIGH: { icon: ShieldAlert, text: "text-sev-high-fg", bg: "bg-sev-high/12", ring: "ring-sev-high/30", hex: "var(--sev-high)" },
  MEDIUM: { icon: AlertTriangle, text: "text-sev-medium-fg", bg: "bg-sev-medium/12", ring: "ring-sev-medium/30", hex: "var(--sev-medium)" },
  LOW: { icon: CircleDot, text: "text-sev-low-fg", bg: "bg-sev-low/12", ring: "ring-sev-low/30", hex: "var(--sev-low)" },
  INFO: { icon: Info, text: "text-sev-info-fg", bg: "bg-sev-info/12", ring: "ring-sev-info/30", hex: "var(--sev-info)" },
};

export const VERDICT_META: Record<Verdict, { icon: LucideIcon; label: string; text: string; bg: string; ring: string; hex: string; blurb: string }> = {
  PASS: { icon: ShieldCheck, label: "PASS", text: "text-success", bg: "bg-success/12", ring: "ring-success/30", hex: "var(--success)",
    blurb: "No medium or higher findings. Safe to connect, and pin it to detect future changes." },
  WARN: { icon: AlertTriangle, label: "WARN", text: "text-warning", bg: "bg-warning/12", ring: "ring-warning/30", hex: "var(--warning)",
    blurb: "Medium-severity issues found. Review before connecting this server to an agent." },
  FAIL: { icon: ShieldX, label: "FAIL", text: "text-danger", bg: "bg-danger/12", ring: "ring-danger/30", hex: "var(--danger)",
    blurb: "Critical or high-severity issues found. Do not connect this server to an agent." },
};
