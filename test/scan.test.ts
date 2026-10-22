import { afterEach, describe, expect, it, vi } from "vitest";
import { scanHost } from "../src/scan";

const opt = { userAgent: "test", timeoutMs: 5000, maxBodyBytes: 512 * 1024 };

function resp(body: string, init: ResponseInit & { url?: string } = {}) {
  const r = new Response(body, init);
  if (init.url) Object.defineProperty(r, "url", { value: init.url });
  return r;
}

afterEach(() => vi.unstubAllGlobals());

describe("scanHost with a stubbed network", () => {
  it("falls back to www and confirms WordPress via the login probe", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      calls.push(url);
      if (url === "https://client.com/") throw new TypeError("DNS lookup failed");
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
    expect(calls).toEqual(["https://client.com/", "https://www.client.com/", "https://www.client.com/wp-login.php"]);
    expect(r.verdict).toBe("php-confirmed");
    expect(r.cms).toBe("wordpress");
    expect(r.cloudflare).toBe(true);
    expect(r.errors).toHaveLength(1);
  });

  it("reports a static WordPress export as likely, with a note", async () => {
    vi.stubGlobal("fetch", async (url: string) =>
      url.endsWith("/wp-login.php")
        ? resp("not found", { status: 404 })
        : resp('<script src="/wp-includes/js/x.js"></script>', { headers: { "content-type": "text/html" }, url: "https://static.example.org/" }),
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
    expect(r.errors).toHaveLength(3);
  });
});
