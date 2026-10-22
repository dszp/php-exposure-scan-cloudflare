import {
  type Signal, type Verdict,
  dedupeSignals, detectFromBody, detectFromHeaders, detectFromLoginProbe, summarize,
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
  finalUrl: string | null;
  status: number | null;
  server: string | null;
  poweredBy: string | null;
  cloudflare: boolean;
  loginStatus: number | null;
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

function candidates(host: string): string[] {
  const list = [`https://${host}/`];
  if (!host.startsWith("www.")) list.push(`https://www.${host}/`);
  list.push(`http://${host}/`);
  return list;
}

export async function scanHost(host: string, input: string, opt: ScanOptions): Promise<ScanResult> {
  const started = Date.now();
  const headers = { "user-agent": opt.userAgent, accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" };
  const errors: string[] = [];
  let res: Response | null = null;

  for (const url of candidates(host)) {
    try {
      res = await fetch(url, { headers, redirect: "follow", signal: AbortSignal.timeout(opt.timeoutMs) });
      break;
    } catch (e) {
      errors.push(`${url} → ${errText(e)}`);
    }
  }

  if (!res) {
    const s = summarize(false, [], null);
    return {
      input, host, ...s, finalUrl: null, status: null, server: null, poweredBy: null,
      cloudflare: false, loginStatus: null, signals: [], errors, durationMs: Date.now() - started,
    };
  }

  const finalUrl = res.url || `https://${host}/`;
  const signals: Signal[] = detectFromHeaders(res.headers);
  const ctype = res.headers.get("content-type") ?? "";
  if (/html|xml|text\/plain/i.test(ctype) || !ctype) {
    try {
      signals.push(...detectFromBody(await readLimited(res, opt.maxBodyBytes), finalUrl));
    } catch (e) {
      errors.push(`body read → ${errText(e)}`);
    }
  } else {
    res.body?.cancel().catch(() => {});
  }

  // One extra request: WordPress is the bulk of what matters here, and the
  // login page answers the question even when the homepage hides it.
  let loginStatus: number | null = null;
  try {
    const login = await fetch(new URL("/wp-login.php", finalUrl).toString(), {
      headers, redirect: "manual", signal: AbortSignal.timeout(opt.timeoutMs),
    });
    loginStatus = login.status;
    const body = login.status === 200 ? await readLimited(login, 64 * 1024) : "";
    if (login.status !== 200) login.body?.cancel().catch(() => {});
    signals.push(...detectFromLoginProbe(login.status, login.headers.get("location"), body));
    signals.push(...detectFromHeaders(login.headers).filter((s) => s.strength === "confirms"));
  } catch (e) {
    errors.push(`wp-login.php probe → ${errText(e)}`);
  }

  const unique = dedupeSignals(signals);
  const s = summarize(true, unique, loginStatus);
  return {
    input, host, ...s, finalUrl, status: res.status,
    server: res.headers.get("server"), poweredBy: res.headers.get("x-powered-by"),
    cloudflare: res.headers.has("cf-ray"), loginStatus, signals: unique, errors,
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
