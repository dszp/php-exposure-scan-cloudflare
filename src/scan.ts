import {
  type CnameChain, type Signal, type Verdict,
  dedupeSignals, detectFromBody, detectFromDns, detectFromHeaders, detectFromLoginProbe,
  isPhpCms, phpProbePath, samesitePhpLinks, summarize,
} from "./detect";

export interface ScanOptions {
  userAgent: string;
  timeoutMs: number;
  maxBodyBytes: number;
}

export interface ScanResult {
  input: string;
  host: string;
  verdict: Verdict;
  cms: string | null;
  platform: string | null;
  phpVersion: string | null;
  finalUrl: string | null;
  status: number | null;
  server: string | null;
  poweredBy: string | null;
  cloudflare: boolean;
  loginStatus: number | null;
  dns: string[];
  signals: Signal[];
  notes: string[];
  errors: string[];
  durationMs: number;
}

const errText = (e: unknown) => {
  const msg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  return msg.slice(0, 200);
};

// Reads at most `max` bytes, then cancels the rest of the body.
export async function readLimited(res: Response, max: number): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(Math.min(total, max));
  let off = 0;
  for (const c of chunks) {
    const n = Math.min(c.byteLength, buf.byteLength - off);
    buf.set(c.subarray(0, n), off);
    off += n;
    if (off >= buf.byteLength) break;
  }
  return new TextDecoder().decode(buf);
}

const DOH = "https://cloudflare-dns.com/dns-query";

// CNAME chain for one name via DNS over HTTPS (Workers have no resolver API).
// An A query returns the whole chain, CNAMEs first, in resolution order.
export async function cnameChain(name: string, opt: ScanOptions): Promise<string[]> {
  const res = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=A`, {
    headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(opt.timeoutMs),
  });
  if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
  const body = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
  return (body.Answer ?? [])
    .filter((a) => a.type === 5)
    .map((a) => a.data.toLowerCase().replace(/\.$/, ""))
    .slice(0, 10);
}

interface Homepage {
  res: Response;
  finalUrl: string;
}

// https first; plain http only when https fails to connect.
async function fetchHomepage(name: string, headers: Record<string, string>, opt: ScanOptions, errors: string[]): Promise<Homepage | null> {
  for (const url of [`https://${name}/`, `http://${name}/`]) {
    try {
      const res = await fetch(url, { headers, redirect: "follow", signal: AbortSignal.timeout(opt.timeoutMs) });
      return { res, finalUrl: res.url || url };
    } catch (e) {
      errors.push(`${url} → ${errText(e)}`);
    }
  }
  return null;
}

async function readHomepage(page: Homepage, opt: ScanOptions, errors: string[]): Promise<{ signals: Signal[]; phpLinks: string[] }> {
  const signals = detectFromHeaders(page.res.headers);
  const ctype = page.res.headers.get("content-type") ?? "";
  let phpLinks: string[] = [];
  if (/html|xml|text\/plain/i.test(ctype) || !ctype) {
    try {
      const html = await readLimited(page.res, opt.maxBodyBytes);
      signals.push(...detectFromBody(html, page.finalUrl));
      phpLinks = samesitePhpLinks(html, page.finalUrl);
    } catch (e) {
      errors.push(`body read → ${errText(e)}`);
    }
  } else {
    page.res.body?.cancel().catch(() => {});
  }
  return { signals, phpLinks };
}

// Header-only GET of one path on an origin; returns the PHP headers it proved.
async function probe(url: string, headers: Record<string, string>, opt: ScanOptions): Promise<{ status: number; res: Response; signals: Signal[] }> {
  const res = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(opt.timeoutMs) });
  const path = new URL(url).pathname;
  const signals = detectFromHeaders(res.headers)
    .filter((s) => s.strength === "confirms")
    .map((s) => ({ ...s, source: "probe" as const, detail: `${s.detail} (on ${path})` }));
  return { status: res.status, res, signals };
}

const phpConfirmed = (signals: Signal[]) =>
  signals.some((s) => s.strength === "confirms" && (s.id.startsWith("php:") || (s.id.startsWith("cms:") && isPhpCms(s.id.slice(4)))));

export async function scanHost(host: string, input: string, opt: ScanOptions): Promise<ScanResult> {
  const started = Date.now();
  const headers = { "user-agent": opt.userAgent, accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" };
  const errors: string[] = [];
  const signals: Signal[] = [];
  // Apex and www are always both checked: they can be hosted in different places.
  const base = host.replace(/^www\./, "");
  const names = [base, `www.${base}`];

  // Requests run one after another: Workers allow six connections waiting on
  // headers, and runPool already keeps that many hosts in flight.
  const chains: CnameChain[] = [];
  for (const name of names) {
    try {
      chains.push({ name, targets: await cnameChain(name, opt) });
    } catch (e) {
      errors.push(`DNS ${name} → ${errText(e)}`);
    }
  }
  signals.push(...detectFromDns(chains, base));
  const dns = chains.filter((c) => c.targets.length).map((c) => `${c.name} → ${c.targets.join(" → ")}`);

  // Fetch www separately unless the apex already landed there.
  const pages: Homepage[] = [];
  const apex = await fetchHomepage(base, headers, opt, errors);
  if (apex) pages.push(apex);
  if (!apex || new URL(apex.finalUrl).hostname !== names[1]) {
    const www = await fetchHomepage(names[1], headers, opt, errors);
    if (www) pages.push(www);
  }

  if (!pages.length) {
    const s = summarize(false, signals, null);
    return {
      input, host: base, ...s, finalUrl: null, status: null, server: null, poweredBy: null,
      cloudflare: false, loginStatus: null, dns, signals: dedupeSignals(signals), errors, durationMs: Date.now() - started,
    };
  }

  // One analysis per distinct site the two names end up on.
  const origins = new Map<string, Homepage>();
  for (const p of pages) {
    const key = new URL(p.finalUrl).hostname;
    if (origins.has(key)) p.res.body?.cancel().catch(() => {});
    else origins.set(key, p);
  }
  if (origins.size > 1) {
    const notes = [...origins.values()].map((p) => p.finalUrl).join(" and ");
    signals.push({ id: "info:split-site", strength: "info", source: "probe", detail: `Apex and www serve different sites: ${notes}`.slice(0, 160) });
  }

  let loginStatus: number | null = null;
  for (const page of origins.values()) {
    const home = await readHomepage(page, opt, errors);
    signals.push(...home.signals);

    // WordPress is the bulk of what matters here, and the login page answers
    // the question even when the homepage hides it.
    try {
      const login = await probe(new URL("/wp-login.php", page.finalUrl).toString(), headers, opt);
      loginStatus ??= login.status;
      const body = login.status === 200 ? await readLimited(login.res, 64 * 1024) : "";
      if (login.status !== 200) login.res.body?.cancel().catch(() => {});
      signals.push(...detectFromLoginProbe(login.status, login.res.headers.get("location"), body), ...login.signals);
    } catch (e) {
      errors.push(`wp-login.php probe → ${errText(e)}`);
    }

    // A cached homepage can hide PHP that any request reaching PHP reveals.
    const pagePlatform = home.signals.some((s) => s.id.startsWith("platform:"));
    if (!phpConfirmed(signals) && !pagePlatform && !signals.some((s) => s.source === "dns" && s.id.startsWith("platform:"))) {
      const url = new URL(phpProbePath(home.phpLinks), page.finalUrl).toString();
      try {
        const r = await probe(url, headers, opt);
        r.res.body?.cancel().catch(() => {});
        signals.push(...r.signals);
      } catch (e) {
        errors.push(`${url} probe → ${errText(e)}`);
      }
    }
  }

  const primary = pages[0];
  const unique = dedupeSignals(signals);
  const s = summarize(true, unique, loginStatus);
  return {
    input, host: base, ...s, finalUrl: primary.finalUrl, status: primary.res.status,
    server: primary.res.headers.get("server"), poweredBy: primary.res.headers.get("x-powered-by"),
    cloudflare: primary.res.headers.has("cf-ray"), loginStatus, dns, signals: unique, errors,
    durationMs: Date.now() - started,
  };
}

// Runs fn over items with at most `limit` in flight, reporting each result as
// it completes. Workers allow six connections waiting on headers at once.
export async function runPool<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>, onResult: (r: R) => Promise<void> | void) {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const item = items[next++];
      await onResult(await fn(item));
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}
