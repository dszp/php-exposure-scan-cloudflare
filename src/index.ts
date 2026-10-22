import { authorize, type AuthEnv } from "./auth";
import { toCsv, csvRow, CSV_COLUMNS } from "./csv";
import { normalizeList, splitList } from "./domains";
import { runPool, scanHost, type ScanOptions, type ScanResult } from "./scan";
import { renderPage } from "./ui";

interface Env extends AuthEnv {
  USER_AGENT?: string;
  MAX_DOMAINS?: string;
  CONCURRENCY?: string;
  TIMEOUT_MS?: string;
}

const SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

const num = (v: string | undefined, d: number, min: number, max: number) => {
  const n = Number.parseInt(v ?? "", 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : d;
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body, null, 2), { status, headers: { ...SECURITY_HEADERS, "content-type": "application/json; charset=utf-8" } });

async function readInput(request: Request): Promise<string[]> {
  const ct = request.headers.get("content-type") ?? "";
  const len = Number(request.headers.get("content-length") ?? "0");
  if (len > 1_000_000) throw new Error("Request body too large (1 MB max).");
  if (ct.includes("application/json")) {
    const body = (await request.json()) as { domains?: unknown };
    if (!Array.isArray(body.domains)) throw new Error('JSON body must be {"domains": [ ... ]}.');
    return body.domains.filter((d): d is string => typeof d === "string").flatMap(splitList);
  }
  if (ct.includes("multipart/form-data")) {
    const form = await request.formData();
    return splitList(String(form.get("domains") ?? ""));
  }
  const text = await request.text();
  // `curl -d` sends a raw list labeled as form-encoded; honor a real
  // `domains=` field when present, otherwise treat the body as the list.
  if (ct.includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(text);
    if (params.has("domains")) return splitList(params.get("domains") ?? "");
  }
  return splitList(text);
}

async function handleScan(request: Request, env: Env, ctx: ExecutionContext, who: string): Promise<Response> {
  const maxDomains = num(env.MAX_DOMAINS, 500, 1, 5000);
  let items: string[];
  try {
    items = await readInput(request);
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : "Could not read input." }, 400);
  }
  const { hosts, rejected, overLimit } = normalizeList(items, maxDomains);
  if (overLimit) return json({ error: `Too many domains (${hosts.length}); the limit per request is ${maxDomains}.` }, 413);
  if (!hosts.length) return json({ error: "No valid public domains in the input.", rejected }, 400);

  const opt: ScanOptions = {
    userAgent: env.USER_AGENT || "php-exposure-scan/1.0",
    timeoutMs: num(env.TIMEOUT_MS, 15000, 2000, 60000),
    maxBodyBytes: 512 * 1024,
  };
  const concurrency = num(env.CONCURRENCY, 6, 1, 12);
  console.log(JSON.stringify({ event: "scan", who, count: hosts.length, rejected: rejected.length }));

  const scanOne = async (host: string): Promise<ScanResult> => {
    try {
      return await scanHost(host, host, opt);
    } catch (e) {
      return {
        input: host, host, verdict: "unreachable", cms: null, platform: null, phpVersion: null, finalUrl: null,
        status: null, server: null, poweredBy: null, cloudflare: false, loginStatus: null, dns: [], signals: [], notes: [],
        errors: [`scanner error → ${e instanceof Error ? e.message : String(e)}`.slice(0, 200)], durationMs: 0,
      };
    }
  };

  const format = new URL(request.url).searchParams.get("format") ?? "ndjson";

  if (format === "json" || format === "csv") {
    const results: ScanResult[] = [];
    await runPool(hosts, concurrency, scanOne, (r) => { results.push(r); });
    const order = new Map(hosts.map((h, i) => [h, i]));
    results.sort((a, b) => (order.get(a.host) ?? 0) - (order.get(b.host) ?? 0));
    if (format === "csv") {
      return new Response(toCsv(results), {
        headers: {
          ...SECURITY_HEADERS,
          "content-type": "text/csv; charset=utf-8",
          "content-disposition": 'attachment; filename="php-exposure-scan.csv"',
        },
      });
    }
    return json({ scanned: results.length, rejected, results });
  }

  // Default: newline-delimited JSON, streamed as each host finishes so long
  // lists show progress and the connection never sits idle.
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const writer = writable.getWriter();
  const enc = new TextEncoder();
  const line = (o: unknown) => writer.write(enc.encode(JSON.stringify(o) + "\n"));
  const task = (async () => {
    try {
      await line({ type: "start", total: hosts.length, rejected, csvColumns: CSV_COLUMNS });
      await runPool(hosts, concurrency, scanOne, (r) => line({ type: "result", result: r, csv: csvRow(r) }));
      await line({ type: "done" });
    } catch (e) {
      await line({ type: "error", error: e instanceof Error ? e.message : String(e) }).catch(() => {});
    } finally {
      await writer.close().catch(() => {});
    }
  })();
  ctx.waitUntil(task);
  return new Response(readable, { headers: { ...SECURITY_HEADERS, "content-type": "application/x-ndjson; charset=utf-8" } });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const auth = await authorize(request, env);
    if (!auth.ok) return new Response(auth.reason, { status: auth.status, headers: { ...SECURITY_HEADERS, "content-type": "text/plain; charset=utf-8" } });

    const { pathname } = new URL(request.url);
    if (pathname === "/" && request.method === "GET") {
      const nonce = crypto.randomUUID().replace(/-/g, "");
      return new Response(renderPage(nonce, num(env.MAX_DOMAINS, 500, 1, 5000)), {
        headers: {
          ...SECURITY_HEADERS,
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`,
        },
      });
    }
    if (pathname === "/scan" && request.method === "POST") {
      // A custom header forces a CORS preflight, so another site can't make a
      // signed-in browser start scans with a plain cross-site form POST.
      if (request.headers.get("x-scan-request") !== "1") {
        return new Response("Missing X-Scan-Request: 1 header.", { status: 400, headers: SECURITY_HEADERS });
      }
      return handleScan(request, env, ctx, auth.who);
    }
    if (pathname === "/scan") return new Response("Use POST.", { status: 405, headers: { ...SECURITY_HEADERS, allow: "POST" } });
    return new Response("Not found.", { status: 404, headers: SECURITY_HEADERS });
  },
} satisfies ExportedHandler<Env>;
