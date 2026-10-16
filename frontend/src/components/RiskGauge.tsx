import { motion } from "framer-motion";

/** Semicircular 0-100 risk gauge. Color shifts green -> amber -> red with the score. */
export function RiskGauge({ score, size = 168 }: { score: number; size?: number }) {
  const clamped = Math.max(0, Math.min(100, score));
  const stroke = 14;
  const r = (size - stroke) / 2;
  const cy = size / 2;
  const circumference = Math.PI * r;
  const color = clamped >= 70 ? "var(--danger)" : clamped >= 35 ? "var(--warning)" : "var(--success)";
  const label = clamped >= 70 ? "High risk" : clamped >= 35 ? "Elevated" : "Low risk";
  const arc = `M ${stroke / 2} ${cy} A ${r} ${r} 0 0 1 ${size - stroke / 2} ${cy}`;
  return (
    <div className="relative" style={{ width: size, height: size / 2 + 28 }} role="img" aria-label={`Risk score ${clamped} out of 100, ${label}`}>
      <svg width={size} height={size / 2 + stroke} viewBox={`0 0 ${size} ${size / 2 + stroke}`}>
        <path d={arc} fill="none" stroke="var(--muted)" strokeWidth={stroke} strokeLinecap="round" />
        <motion.path
          d={arc}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference * (1 - clamped / 100) }}
          transition={{ duration: 0.9, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-x-0 text-center" style={{ top: cy - 30 }}>
        <div className="text-4xl font-semibold tabular-nums tracking-tight">{clamped}</div>
        <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{label}</div>
      </div>
      <div className="absolute inset-x-0 bottom-0 flex justify-between px-1 text-[10px] text-muted-foreground tabular-nums">
        <span>0</span>
        <span>100</span>
      </div>
    </div>
  );
}
