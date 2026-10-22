# php-exposure-scan

A Cloudflare Worker that takes a list of domains and reports which ones show signs of running PHP, with WordPress detected specifically. It was built during the October 2026 PHP core RCE response (CVE-2026-109618 / CVE-2026-109619) so client notifications could go to the sites that actually need them.

It is a triage tool, not a vulnerability scanner. It doesn't test for the vulnerability or send exploit payloads, and it requests only the homepage and `/wp-login.php`.

## What each site gets

1. `GET https://host/`, following redirects. If that attempt fails to connect, the scan tries `https://www.host/` and then `http://host/`.
2. `GET /wp-login.php` on the final origin, without following redirects.

That's two requests per reachable site, plus any redirect hops. Requests carry the `USER_AGENT` from `wrangler.jsonc`. Set it to identify you and give a contact URL, so site owners who see the requests in their logs know who sent them.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `php-confirmed` | A response proved PHP: `X-Powered-By: PHP`, PHP in `Server`, a `PHPSESSID` or PHP-framework cookie, a WordPress-only header (`X-Pingback`, REST `Link`), or `wp-login.php` serving the real login form. |
| `php-likely` | Markup from a PHP CMS (WordPress, Drupal, Joomla, Magento, and others) or same-site links to `.php` files, without a header or cookie that proves it. A WordPress static export lands here, with a note. |
| `hosted-platform` | A builder that doesn't expose customer-managed PHP (Squarespace, Wix, Shopify, Webflow, GoDaddy Builder, Weebly, Vercel, Netlify, GitHub Pages). |
| `no-php-signals` | Reachable, but nothing was found. This isn't proof: headers can be stripped, and some WAFs block scanners. |
| `unreachable` | Every attempt failed to connect. The errors are in the result. |

WordPress.com and managed WordPress hosts still show as PHP. They do run PHP, but the host patches it, so read each verdict alongside where the site is hosted.

## Security model

- **Two gates.** Cloudflare Access protects the hostname, and the Worker also verifies the `Cf-Access-Jwt-Assertion` JWT against your team domain and the application's AUD tag. A route that skips Access still gets a 403. If `TEAM_DOMAIN` or `POLICY_AUD` is unset, the Worker refuses every request.
- **Service tokens work.** Access issues the same JWT for service-token requests, so a script or an automation tool such as n8n can call `/scan` with `CF-Access-Client-Id` and `CF-Access-Client-Secret`.
- **No cross-site triggering.** `POST /scan` requires an `X-Scan-Request: 1` header, which a plain cross-site form can't set.
- **Input is limited to public hostnames.** IP literals, single-label names, and internal suffixes (`.local`, `.internal`, `.corp`, `.lan`, and similar) are rejected. A request can hold up to `MAX_DOMAINS` hosts (500 by default).
- **Scan output is untrusted.** Everything in a result came from a third-party site. The UI renders it with `textContent` only, under a nonce-based CSP. The CSV writer prefixes cells that start with `=`, `+`, `-` or `@` so that a spreadsheet won't evaluate them.
- **Logging** records who ran a scan and how many hosts it covered, not the list itself.

## Requirements

- A Cloudflare account on the Workers Paid plan. Free-plan Workers are capped at 50 external subrequests per invocation, which covers about 15 sites.
- A domain on Cloudflare for the scanner's hostname.
- Cloudflare Zero Trust (the free tier is enough) for the Access application.
- Node.js 22.12 or later.

## Set up and deploy

1. Install dependencies and run the checks:

   ```sh
   npm ci
   npm run check    # type-check, tests, and a dry-run build
   ```

2. In `wrangler.jsonc`, replace `php-check.example.com` in `routes` with the hostname you'll use, and set `USER_AGENT` to identify you. If your Cloudflare login has more than one account, add `"account_id"`.
3. In Zero Trust, go to **Access** > **Applications** and create a **Self-hosted** application for that hostname. Add a policy that allows the people who should run scans. Copy the application's **AUD tag**.
4. In `wrangler.jsonc`, set `TEAM_DOMAIN` to `https://<your-team>.cloudflareaccess.com` and `POLICY_AUD` to the AUD tag. Neither value is secret.
5. Log in and deploy:

   ```sh
   npx wrangler login
   npx wrangler deploy
   ```

6. Open `https://<your-hostname>/` and sign in through Access.

`preview_urls` is off so that uploading a version doesn't create an unprotected preview hostname. If you turn it on, protect the preview hostnames in Access too.

## Run a scan

### In the browser

Paste domains, URLs or email addresses, or load a `.txt` or `.csv` export. The page extracts anything that looks like a domain or email address. Results stream in as each site finishes; you can filter by verdict and download the results as CSV or JSON.

### From the command line

`scan.sh` calls the deployed Worker with an Access service token.

1. In Zero Trust, go to **Access** > **Service auth** and create a service token. Add a **Service Auth** policy for that token to the scanner's Access application.
2. Create `scan.env` from the example and fill in the hostname, client ID and client secret:

   ```sh
   cp scan.env.example scan.env && chmod 600 scan.env
   ```

   `scan.env` is git-ignored. If you keep secrets in 1Password, you can make `scan.env.example` a template of `op://` references and fill it with `op inject` instead.

3. Run a scan. Input can contain domains, URLs or email addresses, one or many per line:

   ```sh
   ./scan.sh domains.txt                   # NDJSON, streamed
   ./scan.sh -f csv domains.txt > out.csv  # or -f json
   cat domains.txt | ./scan.sh             # reads stdin when no file is given
   ```

`scan.sh` passes the token headers to curl through a config file descriptor rather than the command line, so the secret doesn't appear in `ps`.

### Through the API

```sh
curl -sN https://<your-hostname>/scan \
  -H "CF-Access-Client-Id: $ID" -H "CF-Access-Client-Secret: $SECRET" \
  -H "X-Scan-Request: 1" -H "Content-Type: application/json" \
  -d '{"domains":["example.com","someone@example.org"]}'
```

The default response is NDJSON streamed per host: a `start` line, one `result` line per host, and a `done` line. To get the whole result at the end instead, add `?format=json` or `?format=csv`. The endpoint also accepts a `text/plain` body of domains, which is what `scan.sh` sends.

## Run locally

`wrangler dev` runs the full pipeline on your machine. To skip the Access check for requests to `localhost`, copy `.dev.vars.example` to `.dev.vars`:

```sh
cp .dev.vars.example .dev.vars
npm run dev
```

The setting in `.dev.vars` takes effect only for `localhost` requests. Don't add it to `wrangler.jsonc`.

## Limits

- Paid Workers default to 10,000 subrequests per invocation. `wrangler.jsonc` raises this Worker's limit to 20,000, which covers 500 hosts in redirect-heavy worst cases.
- A Worker can have at most six requests waiting on response headers at once, so `CONCURRENCY` defaults to 6. With 15-second timeouts, a 500-host run takes a few minutes.

## Tests

`npm test` covers the detection rules, verdict logic, domain normalization, CSV escaping, and the per-host scan flow against a stubbed `fetch`. The test suite doesn't make live requests.

## License

MIT. See [LICENSE](LICENSE).
