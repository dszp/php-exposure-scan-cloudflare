// Single-page UI. All scan data is inserted with textContent, never innerHTML,
// because every field originates from a third-party website.

export function renderPage(nonce: string, maxDomains: number): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP Exposure Scan</title>
<style nonce="${nonce}">
:root{--bg:#f7f7f5;--fg:#1c1c1a;--muted:#6b6b66;--card:#fff;--line:#e2e2dc;--accent:#2f5d8a;
--red:#b3261e;--amber:#9a6200;--green:#2e6b3a;--grey:#6b6b66;--chip:#efefea;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ececea;--muted:#9c9c96;--card:#1f1f1d;
--line:#33332f;--accent:#8fb4dc;--red:#f2867d;--amber:#e3b25c;--green:#86c795;--grey:#9c9c96;--chip:#2a2a27;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:20px;margin:0 0 4px}
p.sub{margin:0 0 16px;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
textarea{width:100%;min-height:140px;resize:vertical;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;
background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:10px}
button,label.btn{font:inherit;border:1px solid var(--line);background:var(--chip);color:var(--fg);
border-radius:8px;padding:7px 12px;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--bg);font-weight:600}
button:disabled{opacity:.5;cursor:default}
input[type=file]{display:none}
.status{color:var(--muted);font-size:14px}
.counts{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 8px}
.pill{border-radius:999px;padding:2px 10px;font-size:13px;background:var(--chip);border:1px solid var(--line);cursor:pointer}
.pill[aria-pressed=true]{outline:2px solid var(--accent)}
.v-php-confirmed{color:var(--red)}.v-php-likely{color:var(--amber)}.v-hosted-platform{color:var(--green)}
.v-no-php-signals{color:var(--grey)}.v-unreachable{color:var(--grey)}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
td.verdict{font-weight:600;white-space:nowrap}
td small{display:block;color:var(--muted)}
details summary{cursor:pointer;color:var(--accent)}
details ul{margin:6px 0 0;padding-left:18px}
.warn{color:var(--amber);font-size:14px;margin-top:8px}
</style>
</head>
<body>
<main>
<h1>PHP Exposure Scan</h1>
<p class="sub">Paste domains, URLs, or email addresses (one per line, or comma separated). Each site gets about two requests: the homepage and <code>/wp-login.php</code>. Up to ${maxDomains} per run.</p>
<div class="card">
<textarea id="input" spellcheck="false" placeholder="example.com&#10;https://www.example.org&#10;someone@clientdomain.com"></textarea>
<div class="row">
<button id="scan" class="primary">Scan</button>
<label class="btn">Load file…<input id="file" type="file" accept=".txt,.csv,text/plain,text/csv"></label>
<button id="csv" disabled>Download CSV</button>
<button id="json" disabled>Download JSON</button>
<span id="status" class="status"></span>
</div>
<div id="warn" class="warn" hidden></div>
</div>
<div id="counts" class="counts"></div>
<div class="tablewrap"><table id="results" hidden>
<thead><tr><th>Site</th><th>Verdict</th><th>CMS / platform</th><th>Evidence</th></tr></thead>
<tbody></tbody></table></div>
</main>
<script nonce="${nonce}">
"use strict";
const $ = (id) => document.getElementById(id);
const VERDICTS = ["php-confirmed","php-likely","hosted-platform","no-php-signals","unreachable"];
const LABEL = {"php-confirmed":"PHP confirmed","php-likely":"PHP likely","hosted-platform":"Hosted platform",
  "no-php-signals":"No PHP signals","unreachable":"Unreachable"};
let rows = [], csvLines = [], csvHeader = "", filter = null;

function el(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = String(text); if (cls) e.className = cls; return e; }

$("file").addEventListener("change", async (ev) => {
  const f = ev.target.files[0]; if (!f) return;
  if (f.size > 1000000) { alert("File is over 1 MB."); return; }
  const text = await f.text();
  // Pull anything that looks like a domain, URL, or email out of a CSV export.
  const found = text.match(/(?:https?:\\/\\/)?(?:[a-z0-9._%+-]+@)?(?:[a-z0-9-]+\\.)+[a-z]{2,63}/gi) || [];
  $("input").value = [...new Set(found.map((s) => s.toLowerCase()))].join("\\n");
});

function renderCounts() {
  const c = $("counts"); c.textContent = "";
  const n = Object.fromEntries(VERDICTS.map((v) => [v, 0]));
  rows.forEach((r) => n[r.verdict]++);
  VERDICTS.forEach((v) => {
    if (!n[v]) return;
    const b = el("button", LABEL[v] + ": " + n[v], "pill v-" + v);
    b.setAttribute("aria-pressed", String(filter === v));
    b.addEventListener("click", () => { filter = filter === v ? null : v; renderCounts(); renderTable(); });
    c.append(b);
  });
}

function renderRow(r) {
  const tr = document.createElement("tr");
  const site = el("td", r.host);
  if (r.finalUrl) site.append(el("small", r.finalUrl));
  const verdict = el("td", LABEL[r.verdict] || r.verdict, "verdict v-" + r.verdict);
  if (r.phpVersion) verdict.append(el("small", "PHP " + r.phpVersion));
  const kind = el("td", [r.cms, r.platform].filter(Boolean).join(" / ") || "—");
  if (r.status != null) kind.append(el("small", "HTTP " + r.status + (r.cloudflare ? " · Cloudflare" : "")));
  const ev = document.createElement("td");
  const strong = r.signals.filter((s) => s.strength !== "info");
  ev.append(el("span", strong.length ? strong.map((s) => s.detail).slice(0, 2).join("; ") : (r.notes[0] || r.errors[0] || "")));
  if (r.signals.length || r.notes.length || r.errors.length) {
    const d = document.createElement("details"); d.append(el("summary", "details"));
    const ul = document.createElement("ul");
    r.signals.forEach((s) => ul.append(el("li", "[" + s.strength + "] " + s.id + " — " + s.detail)));
    r.notes.forEach((t) => ul.append(el("li", "note: " + t)));
    r.errors.forEach((t) => ul.append(el("li", "error: " + t)));
    d.append(ul); ev.append(d);
  }
  tr.append(site, verdict, kind, ev);
  return tr;
}

function renderTable() {
  const tb = $("results").tBodies[0]; tb.textContent = "";
  const order = (v) => VERDICTS.indexOf(v);
  rows.filter((r) => !filter || r.verdict === filter)
    .sort((a, b) => order(a.verdict) - order(b.verdict) || a.host.localeCompare(b.host))
    .forEach((r) => tb.append(renderRow(r)));
  $("results").hidden = rows.length === 0;
}

function download(name, type, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
$("csv").addEventListener("click", () => download("php-scan-" + stamp() + ".csv", "text/csv", [csvHeader, ...csvLines].join("\\r\\n") + "\\r\\n"));
$("json").addEventListener("click", () => download("php-scan-" + stamp() + ".json", "application/json", JSON.stringify(rows, null, 2)));

$("scan").addEventListener("click", async () => {
  const text = $("input").value.trim(); if (!text) return;
  rows = []; csvLines = []; filter = null; renderCounts(); renderTable();
  $("warn").hidden = true; $("scan").disabled = true; $("csv").disabled = true; $("json").disabled = true;
  let total = 0;
  try {
    const res = await fetch("/scan", { method: "POST", headers: { "content-type": "text/plain", "x-scan-request": "1" }, body: text });
    if (!res.ok || !(res.headers.get("content-type") || "").includes("ndjson")) {
      const body = await res.text(); let msg = body;
      try { const j = JSON.parse(body); msg = j.error || body; if (j.rejected && j.rejected.length) msg += " (" + j.rejected.length + " entries rejected)"; } catch {}
      throw new Error(msg.slice(0, 300));
    }
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1); if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.type === "start") {
          total = msg.total; csvHeader = msg.csvColumns.join(",");
          if (msg.rejected.length) { $("warn").hidden = false; $("warn").textContent = "Skipped " + msg.rejected.length + ": " + msg.rejected.slice(0, 8).map((r) => r.input + " (" + r.reason + ")").join(", ") + (msg.rejected.length > 8 ? ", …" : ""); }
        } else if (msg.type === "result") {
          rows.push(msg.result); csvLines.push(msg.csv); renderCounts(); renderTable();
        } else if (msg.type === "error") { throw new Error(msg.error); }
        $("status").textContent = rows.length + " / " + total + " scanned";
      }
    }
    $("status").textContent = "Done: " + rows.length + " scanned";
  } catch (e) {
    $("status").textContent = "Error: " + e.message;
  } finally {
    $("scan").disabled = false; $("csv").disabled = rows.length === 0; $("json").disabled = rows.length === 0;
  }
});
</script>
</body>
</html>`;
}
