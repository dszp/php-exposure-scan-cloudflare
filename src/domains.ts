// Turns a pasted or exported list into scannable public hostnames.
// Accepts bare domains, URLs, and email addresses (Autotask exports often have
// those), one per line or separated by commas, semicolons, or whitespace.

export interface Rejected {
  input: string;
  reason: string;
}

const INTERNAL_SUFFIXES = [
  ".local", ".localdomain", ".lan", ".internal", ".intranet", ".corp", ".home",
  ".home.arpa", ".localhost", ".test", ".example", ".invalid",
];

export function splitList(raw: string): string[] {
  return raw.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
}

export function normalizeHost(input: string): { host?: string; reason?: string } {
  let s = input.trim().replace(/^["'<(]+|[">)'.]+$/g, "").toLowerCase();
  if (!s) return { reason: "empty" };
  s = s.replace(/^mailto:/, "");
  if (s.includes("@") && !s.includes("://")) s = s.slice(s.lastIndexOf("@") + 1);
  s = s.replace(/^\*\./, "");

  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(s) ? s : `https://${s}`);
  } catch {
    return { reason: "not a valid hostname" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { reason: "unsupported scheme" };
  if (url.username || url.password) return { reason: "credentials in URL" };

  const host = url.hostname.replace(/\.$/, ""); // URL() has already punycoded IDNs
  if (host.startsWith("[") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return { reason: "IP addresses are not scanned" };
  if (!host.includes(".")) return { reason: "single-label name" };
  if (host === "localhost" || INTERNAL_SUFFIXES.some((x) => host.endsWith(x))) return { reason: "internal-only name" };

  const labels = host.split(".");
  if (labels.some((l) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return { reason: "not a valid hostname" };
  const tld = labels[labels.length - 1];
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return { reason: "not a valid hostname" };
  return { host };
}

export function normalizeList(items: string[], max: number): { hosts: string[]; rejected: Rejected[]; overLimit: boolean } {
  const hosts: string[] = [];
  const seen = new Set<string>();
  const rejected: Rejected[] = [];
  for (const item of items) {
    const r = normalizeHost(item);
    if (!r.host) {
      rejected.push({ input: item.slice(0, 200), reason: r.reason ?? "invalid" });
      continue;
    }
    if (seen.has(r.host)) continue;
    seen.add(r.host);
    hosts.push(r.host);
  }
  return { hosts, rejected, overLimit: hosts.length > max };
}
