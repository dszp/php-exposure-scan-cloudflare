import { createRemoteJWKSet, jwtVerify } from "jose";

export interface AuthEnv {
  TEAM_DOMAIN?: string; // https://<team>.cloudflareaccess.com
  POLICY_AUD?: string; // Access application AUD tag
  DEV_ALLOW_UNAUTHENTICATED?: string; // "true" only in .dev.vars
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksFor = "";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// Fails closed: no configuration means no access. Access in front of the
// Worker is the first gate; this check is the second, so a route or
// workers.dev URL that skips Access still can't be used.
export async function authorize(request: Request, env: AuthEnv): Promise<{ ok: true; who: string } | { ok: false; status: number; reason: string }> {
  const url = new URL(request.url);
  if (env.DEV_ALLOW_UNAUTHENTICATED === "true" && LOCAL_HOSTS.has(url.hostname)) {
    return { ok: true, who: "local-dev" };
  }

  const team = env.TEAM_DOMAIN?.replace(/\/+$/, "");
  if (!team || !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(team) || !env.POLICY_AUD) {
    return { ok: false, status: 500, reason: "Access verification is not configured (TEAM_DOMAIN / POLICY_AUD)." };
  }

  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return { ok: false, status: 403, reason: "Missing Cloudflare Access token." };

  if (!jwks || jwksFor !== team) {
    jwks = createRemoteJWKSet(new URL(`${team}/cdn-cgi/access/certs`));
    jwksFor = team;
  }
  try {
    const { payload } = await jwtVerify(token, jwks, { issuer: team, audience: env.POLICY_AUD });
    const who = typeof payload.email === "string" ? payload.email
      : typeof payload.common_name === "string" ? `service-token:${payload.common_name}` : "unknown";
    return { ok: true, who };
  } catch {
    return { ok: false, status: 403, reason: "Invalid Cloudflare Access token." };
  }
}
