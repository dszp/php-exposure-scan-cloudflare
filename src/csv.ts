import type { ScanResult } from "./scan";

// Cells beginning with these characters can be evaluated as formulas by
// Excel/Sheets. Scan data comes from third-party sites, so neutralize them.
const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(value: unknown): string {
  let s = value == null ? "" : String(value);
  if (FORMULA_START.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const CSV_COLUMNS = [
  "input", "host", "verdict", "cms", "platform", "final_url", "status", "server",
  "x_powered_by", "cloudflare", "login_status", "signals", "notes", "errors", "duration_ms",
] as const;

export function csvRow(r: ScanResult): string {
  return [
    r.input, r.host, r.verdict, r.cms, r.platform, r.finalUrl, r.status, r.server,
    r.poweredBy, r.cloudflare, r.loginStatus,
    r.signals.map((s) => `${s.id}(${s.strength})`).join("; "),
    r.notes.join(" | "), r.errors.join(" | "), r.durationMs,
  ].map(csvCell).join(",");
}

export function toCsv(results: ScanResult[]): string {
  return [CSV_COLUMNS.join(","), ...results.map(csvRow)].join("\r\n") + "\r\n";
}
