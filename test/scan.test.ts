import { afterEach, describe, expect, it, vi } from "vitest";
import { scanHost } from "../src/scan";

const opt = { userAgent: "test", timeoutMs: 5000, maxBodyBytes: 512 * 1024 };

function resp(body: string, init: ResponseInit & { url?: string } = {}) {
  const r = new Response(body, init);
  if (init.url) Object.defineProperty(r, "url", { value: init.url });
  return r;
}

// DoH answer for `name`: the CNAME chain in `cnames`, or no CNAMEs.
function doh(url: string, cnames: Record<string, string[]>) {
  const name = new URL(url).searchParams.get("name") ?? "";
  const answer = (cnames[name] ?? []).map((data) => ({ type: 5, data: `${data}.` }));
  return resp(JSON.stringify({ Status: 0, Answer: answer }), { headers: { "content-type": "application/dns-json" } });
}

// Stubs fetch with DoH handled; `site` answers everything else and records it.
function stub(site: (url: string) => Response, cnames: Record<string, string[]> = {}) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    if (url.startsWith("https://cloudflare-dns.com/")) return doh(url, cnames);
    calls.push(url);
    return site(url);
  });
  return calls;
}

const html = (body: string, url: string) => resp(body, { headers: { "content-type": "text/html" }, url });

afterEach(() => vi.unstubAllGlobals());

describe("scanHost with a stubbed network", () => {
  it("falls back to www and confirms WordPress via the login probe", async () => {
    const calls = stub((url) => {
      if (url === "https://client.com/" || url === "http://client.com/") throw new TypeError("DNS lookup failed");
      if (url === "https://www.client.com/") {
        return resp('<link rel="stylesheet" href="/wp-content/themes/a/style.css">', {
          headers: { "content-type": "text/html", "cf-ray": "x" }, url: "https://www.client.com/",
        });
      }
      if (url === "https://www.client.com/wp-login.php") {
        return resp('<form id="loginform"><input id="user_login"></form>', {
          headers: { "content-type": "text/html", "set-cookie": "wordpress_test_cookie=WP; path=/" },
        });
      }
      throw new Error(`unexpected ${url}`);
    });
    const r = await scanHost("client.com", "client.com", opt);
    expect(calls).toEqual(["https://client.com/", "http://client.com/", "https://www.client.com/", "https://www.client.com/wp-login.php"]);
    expect(r.verdict).toBe("php-confirmed");
    expect(r.cms).toBe("wordpress");
    expect(r.cloudflare).toBe(true);
    expect(r.errors).toHaveLength(2);
  });

  it("does not fetch www again when the apex redirects there", async () => {
    const calls = stub((url) => {
      if (url === "https://client.com/") return html("<p>hi</p>", "https://www.client.com/");
      if (url.endsWith("/wp-login.php") || url.endsWith("/index.php")) return resp("", { status: 404 });
      throw new Error(`unexpected ${url}`);
    });
    await scanHost("client.com", "client.com", opt);
    expect(calls).toEqual(["https://client.com/", "https://www.client.com/wp-login.php", "https://www.client.com/index.php"]);
  });

  it("checks the apex when given www, and scans both when they serve different sites", async () => {
    const calls = stub((url) => {
      if (url === "https://client.com/") return html("<p>apex</p>", "https://client.com/");
      if (url === "https://www.client.com/") return html("<p>www</p>", "https://www.client.com/");
      if (url === "https://www.client.com/index.php") return resp("", { headers: { "x-powered-by": "PHP/7.4.33" } });
      if (url.endsWith("/wp-login.php") || url.endsWith("/index.php")) return resp("", { status: 404 });
      throw new Error(`unexpected ${url}`);
    });
    const r = await scanHost("www.client.com", "www.client.com", opt);
    expect(r.host).toBe("client.com");
    expect(calls).toContain("https://client.com/index.php");
    expect(calls).toContain("https://www.client.com/index.php");
    expect(r.signals.some((s) => s.id === "info:split-site")).toBe(true);
    expect(r.verdict).toBe("php-confirmed");
    expect(r.phpVersion).toBe("7.4.33");
  });

  it("confirms PHP through a same-site .php link when the homepage hides it", async () => {
    const calls = stub((url) => {
      if (url === "https://shop.example.org/") {
        return html('<a href="/account/logout.php">out</a><form action="/contact.php?x=1"></form>', "https://shop.example.org/");
      }
      if (url === "https://shop.example.org/contact.php") return resp("", { headers: { "x-powered-by": "PHP/8.1.2" } });
      if (url.endsWith("/wp-login.php") || url.endsWith("/index.php")) return resp("", { status: 404 });
      throw new Error(`unexpected ${url}`);
    });
    const r = await scanHost("shop.example.org", "shop.example.org", opt);
    expect(calls).not.toContain("https://shop.example.org/account/logout.php");
    expect(r.verdict).toBe("php-confirmed");
    expect(r.phpVersion).toBe("8.1.2");
    expect(r.signals.find((s) => s.id === "php:x-powered-by")?.detail).toMatch(/on \/contact\.php/);
  });

  it("calls a site on a known platform by its www CNAME, despite PHP-looking markup", async () => {
    const calls = stub(
      (url) => {
        if (url === "https://client.com/") return html('<a href="/menu.php">menu</a>', "https://www.client.com/");
        if (url.endsWith("/wp-login.php")) return resp("", { status: 404 });
        throw new Error(`unexpected ${url}`);
      },
      { "www.client.com": ["ext-sq.squarespace.com"] },
    );
    const r = await scanHost("client.com", "client.com", opt);
    expect(r.verdict).toBe("hosted-platform");
    expect(r.platform).toBe("squarespace");
    expect(r.dns).toEqual(["www.client.com → ext-sq.squarespace.com"]);
    expect(r.notes.join(" ")).toMatch(/markup suggests PHP/);
    expect(calls.some((u) => u.endsWith("/menu.php") || u.endsWith("/index.php"))).toBe(false);
  });

  it("reports a static WordPress export as likely, with a note", async () => {
    stub((url) =>
      url.endsWith("/wp-login.php") || url.endsWith("/index.php")
        ? resp("not found", { status: 404 })
        : html('<script src="/wp-includes/js/x.js"></script>', "https://www.static.example.org/"),
    );
    const r = await scanHost("static.example.org", "static.example.org", opt);
    expect(r.verdict).toBe("php-likely");
    expect(r.loginStatus).toBe(404);
    expect(r.notes.join(" ")).toMatch(/static export/);
  });

  it("marks a host unreachable when every attempt fails", async () => {
    vi.stubGlobal("fetch", async () => { throw new TypeError("connect failed"); });
    const r = await scanHost("gone.example.net", "gone.example.net", opt);
    expect(r.verdict).toBe("unreachable");
    // Two DNS lookups, then https and http for both the apex and www.
    expect(r.errors).toHaveLength(6);
  });
});
