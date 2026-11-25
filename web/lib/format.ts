export const ATTACK_LABELS: Record<string, string> = {
  port_scan: "Port scan",
  ssh_brute_force: "SSH brute force",
  sql_injection: "SQL injection",
  dns_tunneling: "DNS tunneling",
  syn_flood: "SYN flood",
  other: "Other",
};

export const TRUTH_LABELS: Record<string, string> = {
  scan: "Port scan",
  bruteforce: "Brute force",
  flood: "SYN flood",
  web_attack: "SQL injection",
  dns_tunnel: "DNS tunneling",
};

export const ATTACK_CHOICES = [
  { id: "scan", label: "Port scan", note: "Probes a few hundred ports in a second." },
  { id: "slow_scan", label: "Slow port scan", note: "One port every couple of seconds. Takes about a minute; signatures stay quiet." },
  { id: "bruteforce", label: "Brute force", note: "Repeated login attempts, mostly against SSH." },
  { id: "web_attack", label: "SQL injection", note: "Malicious requests to a web app. Only a signature can see it." },
  { id: "dns_tunnel", label: "DNS tunneling", note: "Data smuggled out in long DNS names. Logged, not blocked." },
  { id: "flood", label: "SYN flood", note: "Hundreds of half-open connections per second." },
] as const;

export const attackLabel = (key: string) => ATTACK_LABELS[key] ?? key.replace(/_/g, " ");

export function relTime(ts: number, now = Date.now() / 1000): string {
  const s = Math.max(0, Math.round(now - ts));
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const clock = (ts: number) =>
  new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export const hourLabel = (ts: number) =>
  new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

export const num = (n: number) => n.toLocaleString("en-US");
export const pct = (v: number) => `${Math.round(v * 100)}%`;

export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  const m = Math.round(seconds / 60);
  return m < 60 ? `${m} min` : `${Math.round(m / 6) / 10} h`;
}

export const isBlockedAction = (a: string) => a.includes("block");
