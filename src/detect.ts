// Pure detection logic: no network access, so it can be unit tested in Node.
// Every string that reaches a Signal came from a third-party site and must be
// treated as untrusted when rendered (the UI uses textContent only, and the CSV
// writer neutralizes formula prefixes).

export type Strength = "confirms" | "suggests" | "info";

export interface Signal {
  id: string; // "php:...", "cms:<name>", "platform:<name>", or "info:..."
  strength: Strength;
  source: "header" | "cookie" | "body" | "probe" | "dns";
  detail: string;
}

const MAX_DETAIL = 160;
const clip = (s: string) => (s.length > MAX_DETAIL ? s.slice(0, MAX_DETAIL) + "…" : s);

// CMSs and frameworks that run on PHP.
const PHP_CMS = new Set([
  "wordpress", "drupal", "joomla", "magento", "typo3", "prestashop", "mediawiki",
  "phpbb", "concrete", "craft", "laravel", "codeigniter", "cakephp", "opencart", "moodle",
  "nextcloud",
]);

export function isPhpCms(name: string): boolean {
  return PHP_CMS.has(name);
}

// ---------- headers & cookies ----------

export function cookieNames(setCookies: string[]): string[] {
  return setCookies
    .map((c) => c.split(";", 1)[0].split("=", 1)[0].trim())
    .filter(Boolean);
}

export function detectFromHeaders(headers: Headers): Signal[] {
  const out: Signal[] = [];
  const h = (n: string) => headers.get(n);

  const powered = h("x-powered-by");
  if (powered) {
    if (/php/i.test(powered)) {
      out.push({ id: "php:x-powered-by", strength: "confirms", source: "header", detail: clip(`X-Powered-By: ${powered}`) });
    } else {
      out.push({ id: "info:x-powered-by", strength: "info", source: "header", detail: clip(`X-Powered-By: ${powered}`) });
    }
  }

  const server = h("server");
  if (server && /\bPHP\/\d/i.test(server)) {
    out.push({ id: "php:server-header", strength: "confirms", source: "header", detail: clip(`Server: ${server}`) });
  }

  if (h("x-pingback")) {
    out.push({ id: "cms:wordpress", strength: "confirms", source: "header", detail: "X-Pingback header (WordPress XML-RPC)" });
  }
  const link = h("link");
  if (link && /api\.w\.org/i.test(link)) {
    out.push({ id: "cms:wordpress", strength: "confirms", source: "header", detail: "Link header to WordPress REST API" });
  }
  if (h("x-drupal-cache") || h("x-drupal-dynamic-cache") || /drupal/i.test(h("x-generator") ?? "")) {
    out.push({ id: "cms:drupal", strength: "confirms", source: "header", detail: "Drupal response header" });
  }
  for (const [name] of headers) {
    if (name.startsWith("x-magento")) {
      out.push({ id: "cms:magento", strength: "confirms", source: "header", detail: clip(`${name} header`) });
      break;
    }
  }

  // Hosted platforms that do not expose customer-managed PHP.
  if (h("x-shopify-stage") || h("x-shopid") || /shopify/i.test(h("powered-by") ?? "")) {
    out.push({ id: "platform:shopify", strength: "info", source: "header", detail: "Shopify response header" });
  }
  if (h("x-wix-request-id")) {
    out.push({ id: "platform:wix", strength: "info", source: "header", detail: "Wix response header" });
  }
  if (server && /squarespace/i.test(server)) {
    out.push({ id: "platform:squarespace", strength: "info", source: "header", detail: clip(`Server: ${server}`) });
  }
  if (h("x-vercel-id")) out.push({ id: "platform:vercel", strength: "info", source: "header", detail: "Vercel response header" });
  if (h("x-nf-request-id")) out.push({ id: "platform:netlify", strength: "info", source: "header", detail: "Netlify response header" });
  if (h("x-github-request-id")) out.push({ id: "platform:github-pages", strength: "info", source: "header", detail: "GitHub Pages response header" });

  const names = cookieNames(headers.getSetCookie());
  for (const name of names) {
    const n = name.toLowerCase();
    if (n === "phpsessid") {
      out.push({ id: "php:phpsessid-cookie", strength: "confirms", source: "cookie", detail: "PHPSESSID session cookie" });
    } else if (n.startsWith("wordpress_") || n.startsWith("wp-settings") || n.startsWith("woocommerce")) {
      out.push({ id: "cms:wordpress", strength: "confirms", source: "cookie", detail: clip(`Cookie ${name}`) });
    } else if (n === "laravel_session") {
      out.push({ id: "cms:laravel", strength: "confirms", source: "cookie", detail: "laravel_session cookie" });
    } else if (n === "ci_session") {
      out.push({ id: "cms:codeigniter", strength: "confirms", source: "cookie", detail: "ci_session cookie" });
    } else if (n === "cakephp") {
      out.push({ id: "cms:cakephp", strength: "confirms", source: "cookie", detail: "CAKEPHP cookie" });
    } else if (/^s?sess[0-9a-f]{32}$/.test(n)) {
      out.push({ id: "cms:drupal", strength: "confirms", source: "cookie", detail: "Drupal session cookie" });
    } else if (n.startsWith("prestashop-")) {
      out.push({ id: "cms:prestashop", strength: "confirms", source: "cookie", detail: clip(`Cookie ${name}`) });
    } else if (n === "moodlesession") {
      out.push({ id: "cms:moodle", strength: "confirms", source: "cookie", detail: "MoodleSession cookie" });
    }
  }

  if (h("cf-ray")) {
    out.push({ id: "info:cloudflare", strength: "info", source: "header", detail: "Fronted by Cloudflare" });
  }
  return out;
}

// ---------- body ----------

const GENERATOR_RULES: Array<[RegExp, string, "cms" | "platform"]> = [
  [/wordpress/i, "wordpress", "cms"],
  [/drupal/i, "drupal", "cms"],
  [/joomla/i, "joomla", "cms"],
  [/typo3/i, "typo3", "cms"],
  [/prestashop/i, "prestashop", "cms"],
  [/mediawiki/i, "mediawiki", "cms"],
  [/phpbb/i, "phpbb", "cms"],
  [/concrete/i, "concrete", "cms"],
  [/craft cms/i, "craft", "cms"],
  [/magento/i, "magento", "cms"],
  [/opencart/i, "opencart", "cms"],
  [/wix\.com/i, "wix", "platform"],
  [/squarespace/i, "squarespace", "platform"],
  [/webflow/i, "webflow", "platform"],
  [/go ?daddy|starfield/i, "godaddy-builder", "platform"],
  [/weebly/i, "weebly", "platform"],
  [/duda/i, "duda", "platform"],
  [/ghost/i, "ghost", "platform"],
  [/hugo|jekyll|gatsby|next\.js|hexo|docusaurus|eleventy|astro/i, "static-site-generator", "platform"],
];

const BODY_RULES: Array<[RegExp, string, Strength, string]> = [
  [/\/wp-content\/|\/wp-includes\//i, "cms:wordpress", "suggests", "wp-content / wp-includes asset paths"],
  [/api\.w\.org/i, "cms:wordpress", "suggests", "WordPress REST API link in HTML"],
  [/\/sites\/(?:default|all)\/(?:files|themes|modules)\//i, "cms:drupal", "suggests", "Drupal asset paths"],
  [/drupal-settings-json|Drupal\.settings/i, "cms:drupal", "suggests", "Drupal settings script"],
  [/\/media\/jui\/|\/components\/com_[a-z]/i, "cms:joomla", "suggests", "Joomla asset paths"],
  [/Mage\.Cookies|data-mage-init|\/static\/version\d+\/frontend\/|\/skin\/frontend\//i, "cms:magento", "suggests", "Magento markup"],
  [/livewire\/livewire(?:\.min)?\.js/i, "cms:laravel", "suggests", "Laravel Livewire script"],
  [/\/pluginfile\.php\/|M\.cfg\s*=/i, "cms:moodle", "suggests", "Moodle markup"],
  [/static1\.squarespace\.com/i, "platform:squarespace", "info", "Squarespace asset host"],
  [/static\.wixstatic\.com|parastorage\.com/i, "platform:wix", "info", "Wix asset host"],
  [/cdn\.shopify\.com/i, "platform:shopify", "info", "Shopify asset host"],
  [/website-files\.com|webflow\.com\/css/i, "platform:webflow", "info", "Webflow asset host"],
  [/img1\.wsimg\.com/i, "platform:godaddy-builder", "info", "GoDaddy Website Builder asset host"],
  [/editmysite\.com/i, "platform:weebly", "info", "Weebly/Square Online asset host"],
];

function generatorValues(html: string): string[] {
  const out: string[] = [];
  const re = /<meta\b[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) && out.length < 5) {
    const tag = m[0];
    if (!/name\s*=\s*["']?generator["']?/i.test(tag)) continue;
    const c = /content\s*=\s*["']([^"']{1,200})["']/i.exec(tag);
    if (c) out.push(c[1]);
  }
  return out;
}

const SAME_SITE = (a: string, b: string) => a.replace(/^www\./, "") === b.replace(/^www\./, "");

// Same-site links to .php files. Third-party .php URLs (share buttons and the
// like) are ignored because they say nothing about this site's stack.
export function samesitePhpLinks(html: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const found = new Set<string>();
  const re = /\b(?:href|src|action)\s*=\s*["']([^"'<>\s]{1,300})["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) && found.size < 5) {
    let u: URL;
    try {
      u = new URL(m[1], base);
    } catch {
      continue;
    }
    if (!/^https?:$/.test(u.protocol)) continue;
    if (!SAME_SITE(u.hostname, base.hostname)) continue;
    if (/\.php$/i.test(u.pathname)) found.add(u.pathname);
  }
  return [...found];
}

export function detectFromBody(html: string, baseUrl: string): Signal[] {
  const out: Signal[] = [];
  for (const g of generatorValues(html)) {
    const rule = GENERATOR_RULES.find(([re]) => re.test(g));
    if (!rule) {
      out.push({ id: "info:generator", strength: "info", source: "body", detail: clip(`Generator: ${g}`) });
    } else if (rule[2] === "cms") {
      out.push({ id: `cms:${rule[1]}`, strength: "suggests", source: "body", detail: clip(`Generator: ${g}`) });
    } else {
      out.push({ id: `platform:${rule[1]}`, strength: "info", source: "body", detail: clip(`Generator: ${g}`) });
    }
  }
  for (const [re, id, strength, detail] of BODY_RULES) {
    if (re.test(html)) out.push({ id, strength, source: "body", detail });
  }
  const links = samesitePhpLinks(html, baseUrl);
  if (links.length) {
    out.push({ id: "php:same-site-links", strength: "suggests", source: "body", detail: clip(`Links to ${links.join(", ")}`) });
  }
  return out;
}

// ---------- wp-login.php probe ----------

export function detectFromLoginProbe(status: number, location: string | null, body: string): Signal[] {
  if (status === 200 && /id=["']?user_login|name=["']?wp-submit|id=["']?loginform/i.test(body)) {
    return [{ id: "cms:wordpress", strength: "confirms", source: "probe", detail: "wp-login.php serves the WordPress login form" }];
  }
  if (status === 401) {
    return [{ id: "info:login-auth", strength: "info", source: "probe", detail: "wp-login.php returns 401 (HTTP auth in front of it)" }];
  }
  // Only the redirect's path counts: a site search for the missing page can
  // carry "wp-login.php" in its query string.
  const path = location ? (() => { try { return new URL(location, "https://x/").pathname; } catch { return ""; } })() : "";
  if (status >= 300 && status < 400 && /wp-login|wp-admin/i.test(path)) {
    return [{ id: "cms:wordpress", strength: "suggests", source: "probe", detail: clip(`wp-login.php redirects to ${location}`) }];
  }
  return [];
}

// ---------- follow-up .php probe ----------

// Paths a GET could change state on, or that WordPress handles specially.
const UNSAFE_PROBE = /log-?out|log-?off|sign-?out|delete|remove|unsubscribe|cancel|destroy|reset|wp-login\.php$|wp-cron\.php$|xmlrpc\.php$|admin-ajax\.php$|wp-comments-post\.php$/i;

// A homepage served from a page cache often lacks the PHP headers that any
// request reaching PHP itself carries. Picks one same-site .php path to GET
// (never a form submission, and without the query string), else /index.php.
export function phpProbePath(links: string[]): string {
  return links.find((p) => !UNSAFE_PROBE.test(p)) ?? "/index.php";
}

// ---------- DNS ----------

export interface CnameChain {
  name: string;
  targets: string[]; // CNAME targets in resolution order
}

// CNAME targets that identify where a site is hosted. Page markup misses
// builders that render generic HTML; the DNS target doesn't.
const DNS_RULES: Array<{ re: RegExp; label: string; signals: Array<[string, Strength]> }> = [
  { re: /(?:^|\.)squarespace\.com$/, label: "Squarespace", signals: [["platform:squarespace", "info"]] },
  { re: /(?:^|\.)wixdns\.net$/, label: "Wix", signals: [["platform:wix", "info"]] },
  { re: /(?:^|\.)webflow\.com$/, label: "Webflow", signals: [["platform:webflow", "info"]] },
  { re: /(?:^|\.)multiscreensite\.com$/, label: "Duda", signals: [["platform:duda", "info"]] },
  { re: /(?:^|\.)(?:hubspot\.net|hscoscdn\d*\.net)$/, label: "HubSpot CMS", signals: [["platform:hubspot", "info"]] },
  { re: /(?:^|\.)myshopify\.com$/, label: "Shopify", signals: [["platform:shopify", "info"]] },
  { re: /(?:^|\.)azurestaticapps\.net$/, label: "Azure Static Web Apps", signals: [["platform:azure-static-web-apps", "info"]] },
  { re: /(?:^|\.)vercel-dns\.com$/, label: "Vercel", signals: [["platform:vercel", "info"]] },
  { re: /(?:^|\.)netlify\.(?:app|com)$/, label: "Netlify", signals: [["platform:netlify", "info"]] },
  { re: /(?:^|\.)github\.io$/, label: "GitHub Pages", signals: [["platform:github-pages", "info"]] },
  { re: /(?:^|\.)hugedomains\.com$/, label: "HugeDomains for-sale page", signals: [["platform:parked", "info"]] },
  // Managed PHP hosts: PHP, but the host maintains it.
  { re: /(?:^|\.)(?:wpengine\.com|wpenginepowered\.com)$/, label: "WP Engine", signals: [["cms:wordpress", "suggests"], ["info:managed-php-host", "info"]] },
  { re: /(?:^|\.)pantheonsite\.io$/, label: "Pantheon", signals: [["php:managed-host", "suggests"], ["info:managed-php-host", "info"]] },
  // Can run PHP; the target alone says nothing more.
  { re: /\.azurewebsites\.(?:net|windows\.net)$/, label: "Azure App Service", signals: [["info:azure-app-service", "info"]] },
];

// `base` is the scanned domain; CNAMEs that stay inside it (www → apex) are not
// hosting evidence. Every chain that leaves it is reported, matched or not, so
// a reader can spot a vendor the rules don't know.
export function detectFromDns(chains: CnameChain[], base: string): Signal[] {
  const own = (h: string) => h === base || h.endsWith(`.${base}`);
  const out: Signal[] = [];
  for (const { name, targets } of chains) {
    if (!targets.some((t) => !own(t))) continue;
    out.push({ id: "info:cname", strength: "info", source: "dns", detail: clip(`${name} → ${targets.join(" → ")}`) });
    for (const t of targets) {
      const rule = DNS_RULES.find((r) => r.re.test(t));
      if (!rule) continue;
      for (const [id, strength] of rule.signals) {
        out.push({ id, strength, source: "dns", detail: clip(`${name} → ${t} (${rule.label})`) });
      }
      break;
    }
  }
  return out;
}

// ---------- verdict ----------

export type Verdict =
  | "php-confirmed"
  | "php-likely"
  | "hosted-platform"
  | "no-php-signals"
  | "unreachable";

export interface Summary {
  verdict: Verdict;
  cms: string | null;
  platform: string | null;
  phpVersion: string | null;
  notes: string[];
}

// Lowest PHP version any response admitted to, since the oldest one is the
// one that needs attention.
export function phpVersionOf(signals: Signal[]): string | null {
  const versions = signals
    .filter((s) => s.id === "php:x-powered-by" || s.id === "php:server-header")
    .map((s) => /PHP\/(\d+(?:\.\d+){0,2})/i.exec(s.detail)?.[1])
    .filter((v): v is string => !!v);
  return versions.sort((a, b) => a.localeCompare(b, "en", { numeric: true }))[0] ?? null;
}

export function dedupeSignals(signals: Signal[]): Signal[] {
  const seen = new Set<string>();
  return signals.filter((s) => {
    const k = `${s.id}|${s.source}|${s.detail}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function summarize(reachable: boolean, signals: Signal[], loginStatus: number | null): Summary {
  const notes: string[] = [];
  const cmsSignals = signals.filter((s) => s.id.startsWith("cms:"));
  const rank: Record<Strength, number> = { confirms: 0, suggests: 1, info: 2 };
  const cms = cmsSignals.length
    ? [...cmsSignals].sort((a, b) => rank[a.strength] - rank[b.strength])[0].id.slice(4)
    : null;
  // A CNAME to a hosting platform outranks what the page markup implies.
  const dnsPlatform = signals.find((s) => s.source === "dns" && s.id.startsWith("platform:"));
  const platform = (dnsPlatform ?? signals.find((s) => s.id.startsWith("platform:")))?.id.slice(9) ?? null;
  const phpVersion = phpVersionOf(signals);
  const verdict = (v: Verdict): Summary => ({ verdict: v, cms, platform, phpVersion, notes });

  if (!reachable) return verdict("unreachable");

  for (const s of signals) {
    if (s.id === "info:managed-php-host") notes.push(`Managed PHP host per DNS (${s.detail}); the host maintains PHP.`);
  }

  // A non-PHP CMS name can't confirm PHP, but every cms:* id here is a PHP one.
  const phpish = (s: Signal) => s.id.startsWith("php:") || (s.id.startsWith("cms:") && isPhpCms(s.id.slice(4)));
  const confirmed = signals.some((s) => phpish(s) && s.strength === "confirms");
  const suggested = signals.some((s) => phpish(s) && s.strength === "suggests");

  if (confirmed) {
    if (dnsPlatform) notes.push(`DNS points at a hosted platform (${dnsPlatform.detail}), so the vendor likely runs this PHP.`);
    return verdict("php-confirmed");
  }

  if (dnsPlatform) {
    if (suggested) notes.push(`Page markup suggests PHP, but DNS points at a hosted platform (${dnsPlatform.detail}).`);
    return verdict("hosted-platform");
  }

  if (suggested) {
    if (cms === "wordpress" && !signals.some((s) => s.source !== "body" && s.id === "cms:wordpress")) {
      notes.push(
        loginStatus === 404 || loginStatus === 410
          ? "WordPress markers in the HTML only, and wp-login.php is not found: possibly a static export or a hardened login path."
          : "WordPress markers in the HTML only; no PHP header or cookie seen.",
      );
    }
    return verdict("php-likely");
  }

  if (platform && platform !== "static-site-generator") return verdict("hosted-platform");
  notes.push("No PHP signals found. Absence is not proof: headers can be suppressed and some sites block scanners.");
  return verdict("no-php-signals");
}
