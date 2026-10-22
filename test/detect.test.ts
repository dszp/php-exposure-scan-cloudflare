import { describe, expect, it } from "vitest";
import { detectFromBody, detectFromHeaders, detectFromLoginProbe, samesitePhpLinks, summarize } from "../src/detect";
import { normalizeHost, normalizeList, splitList } from "../src/domains";
import { csvCell } from "../src/csv";

const hdrs = (pairs: Array<[string, string]>) => {
  const h = new Headers();
  for (const [k, v] of pairs) h.append(k, v);
  return h;
};
const ids = (s: { id: string; strength: string }[]) => s.map((x) => `${x.id}/${x.strength}`);

describe("headers", () => {
  it("confirms PHP from X-Powered-By and PHPSESSID", () => {
    const s = detectFromHeaders(hdrs([["x-powered-by", "PHP/8.3.12"], ["set-cookie", "PHPSESSID=abc; path=/; HttpOnly"]]));
    expect(ids(s)).toEqual(expect.arrayContaining(["php:x-powered-by/confirms", "php:phpsessid-cookie/confirms"]));
  });
  it("confirms WordPress from X-Pingback, Link, and cookies", () => {
    const s = detectFromHeaders(hdrs([
      ["x-pingback", "https://x.com/xmlrpc.php"],
      ["link", '<https://x.com/wp-json/>; rel="https://api.w.org/"'],
      ["set-cookie", "wordpress_test_cookie=WP%20Cookie; path=/"],
    ]));
    expect(s.filter((x) => x.id === "cms:wordpress" && x.strength === "confirms")).toHaveLength(3);
  });
  it("spots PHP in the Server header and Drupal session cookies", () => {
    const s = detectFromHeaders(hdrs([["server", "Apache/2.4.62 (Debian) PHP/7.4.33"], ["set-cookie", "SSESSabcdef0123456789abcdef0123456789=x"]]));
    expect(ids(s)).toEqual(expect.arrayContaining(["php:server-header/confirms", "cms:drupal/confirms"]));
  });
  it("labels hosted platforms as info only", () => {
    const s = detectFromHeaders(hdrs([["server", "Squarespace"], ["cf-ray", "abc-ORD"]]));
    expect(ids(s)).toEqual(["platform:squarespace/info", "info:cloudflare/info"]);
  });
});

describe("body", () => {
  it("finds WordPress assets and generator", () => {
    const html = '<meta name="generator" content="WordPress 6.8.1"><link href="/wp-content/themes/x/style.css">';
    expect(ids(detectFromBody(html, "https://example.com/"))).toEqual(
      expect.arrayContaining(["cms:wordpress/suggests"]),
    );
  });
  it("handles content-before-name generator order", () => {
    const html = '<meta content="Joomla! - Open Source Content Management" name="generator">';
    expect(ids(detectFromBody(html, "https://example.com/"))).toContain("cms:joomla/suggests");
  });
  it("counts only same-site .php links", () => {
    const html = `<a href="https://www.facebook.com/sharer/sharer.php?u=x">share</a>
      <a href="/contact.php">contact</a><form action="https://www.example.com/send.php"></form>`;
    expect(samesitePhpLinks(html, "https://example.com/")).toEqual(["/contact.php", "/send.php"]);
  });
  it("recognizes non-PHP builders", () => {
    expect(ids(detectFromBody('<img src="https://static1.squarespace.com/a.jpg">', "https://x.com/"))).toEqual(["platform:squarespace/info"]);
  });
});

describe("login probe", () => {
  it("confirms the WordPress login form", () => {
    expect(ids(detectFromLoginProbe(200, null, '<form name="loginform" id="loginform"><input id="user_login">'))).toEqual(["cms:wordpress/confirms"]);
  });
  it("notes HTTP auth", () => {
    expect(ids(detectFromLoginProbe(401, null, ""))).toEqual(["info:login-auth/info"]);
  });
  it("ignores 404 and unrelated redirects", () => {
    expect(detectFromLoginProbe(404, null, "")).toEqual([]);
    expect(detectFromLoginProbe(301, "https://example.com/", "")).toEqual([]);
  });
});

describe("summarize", () => {
  it("ranks confirmed over likely", () => {
    const s = summarize(true, [
      { id: "cms:wordpress", strength: "suggests", source: "body", detail: "" },
      { id: "php:phpsessid-cookie", strength: "confirms", source: "cookie", detail: "" },
    ], 200);
    expect(s.verdict).toBe("php-confirmed");
    expect(s.cms).toBe("wordpress");
  });
  it("flags WordPress markers without PHP evidence as a possible static export", () => {
    const s = summarize(true, [{ id: "cms:wordpress", strength: "suggests", source: "body", detail: "" }], 404);
    expect(s.verdict).toBe("php-likely");
    expect(s.notes[0]).toMatch(/static export/);
  });
  it("reports hosted platforms and plain no-signal sites separately", () => {
    expect(summarize(true, [{ id: "platform:wix", strength: "info", source: "header", detail: "" }], 404).verdict).toBe("hosted-platform");
    expect(summarize(true, [], 404).verdict).toBe("no-php-signals");
    expect(summarize(false, [], null).verdict).toBe("unreachable");
  });
});

describe("domain input", () => {
  it("normalizes URLs, emails, and wildcards", () => {
    expect(normalizeHost("https://WWW.Example.com/path?q=1").host).toBe("www.example.com");
    expect(normalizeHost("jane.doe@ClientCo.org").host).toBe("clientco.org");
    expect(normalizeHost("*.example.net").host).toBe("example.net");
    expect(normalizeHost("example.com.").host).toBe("example.com");
    expect(normalizeHost("bücher.de").host).toBe("xn--bcher-kva.de");
  });
  it("rejects IPs, internal names, and junk", () => {
    for (const bad of ["10.0.0.5", "[::1]", "localhost", "fileserver", "contoso.local", "corp.internal", "ftp://x.com", "https://user:pw@x.com/"]) {
      expect(normalizeHost(bad).host, bad).toBeUndefined();
    }
  });
  it("splits, dedupes, and enforces the limit", () => {
    const items = splitList("a.com, b.com;a.com\nhttps://c.com  bad");
    const r = normalizeList(items, 2);
    expect(r.hosts).toEqual(["a.com", "b.com", "c.com"]);
    expect(r.rejected).toHaveLength(1);
    expect(r.overLimit).toBe(true);
  });
});

describe("csv", () => {
  it("neutralizes formulas and quotes properly", () => {
    expect(csvCell("=HYPERLINK(\"x\")")).toBe("\"'=HYPERLINK(\"\"x\"\")\"");
    expect(csvCell("-1")).toBe("'-1");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell(null)).toBe("");
  });
});
