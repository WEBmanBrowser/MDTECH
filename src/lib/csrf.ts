/**
 * P1 — CSRF protection for browser state-changing requests.
 *
 * Strategy (App Router + SameSite=Lax cookies + Cloudflare Workers):
 * For POST/PUT/PATCH/DELETE requests that present browser credentials
 * (the auth cookie), validate that the request Origin matches the server
 * Host. Fail-CLOSED: a browser-shaped request with no Origin header is
 * rejected — same-site fetch/XHR/form posts always send Origin on
 * state-changing methods; only crafted cross-site requests omit it.
 *
 * NOT applied to (checked in order):
 *  - GET/HEAD/OPTIONS (safe methods)
 *  - requests whose secret credential is actually VALIDATED (cron / internal
 *    APIs): x-cron-secret must MATCH the configured CRON_SECRET/JWT_SECRET.
 *    Mere PRESENCE of a secret header NEVER bypasses the check — the
 *    credential must actually verify. A Bearer header alone never bypasses:
 *    Bearer callers without a cookie are already covered by the non-browser
 *    rule below, and Bearer + cookie is browser-shaped (Origin required).
 *  - non-browser clients (no cookie AND no Origin): they are not CSRF-able;
 *    their authorization is handled by their own auth (JWT header etc.)
 *
 * Returns null when allowed, or a ready 403 NextResponse when blocked.
 */
import { NextRequest, NextResponse } from "next/server";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Hosts always allowed regardless of Origin (cron, health checks). */
const TRUSTED_HOST_SUFFIXES = [".workers.dev"];

function isTrustedHost(host: string): boolean {
  const h = host.toLowerCase();
  return TRUSTED_HOST_SUFFIXES.some((s) => h.endsWith(s));
}

/**
 * Compare Origin against Host. Both normalized: scheme stripped from Origin,
 * port compared exactly (localhost dev ports must match).
 */
function originMatchesHost(origin: string, host: string): boolean {
  try {
    const o = new URL(origin);
    return o.host === host.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Validate the x-cron-secret credential against the configured secret.
 * Returns true ONLY on an exact match — presence alone is never enough.
 */
function cronSecretValidates(cronSecret: string): boolean {
  const expected = process.env.CRON_SECRET || process.env.JWT_SECRET;
  if (!expected || !cronSecret) return false;
  return cronSecret === expected;
}

/**
 * CSRF guard. Call at the top of state-changing route handlers.
 *
 * @param req incoming NextRequest
 * @param opts.allowSecretAuth allow the check to be skipped when the request
 *        carries a VALIDATED secret credential (cron/webhook/internal API).
 *        Default true. Validation is exact-match against CRON_SECRET/JWT_SECRET —
 *        a forged or absent secret falls through to the Origin check.
 * @returns null to continue, or a 403 NextResponse to return immediately.
 */
export function csrfGuard(
  req: NextRequest,
  opts: { allowSecretAuth?: boolean } = {}
): NextResponse | null {
  const method = req.method.toUpperCase();
  if (SAFE_METHODS.has(method)) return null;

  const cookie = req.cookies.get("auth_token")?.value;
  const origin = req.headers.get("origin");
  const host = req.headers.get("host") || "";

  // Secret-authenticated callers (cron, webhooks, internal APIs): the secret
  // must actually VERIFY — a forged x-cron-secret does not bypass.
  if (opts.allowSecretAuth !== false) {
    const cronSecret = req.headers.get("x-cron-secret");
    if (cronSecret && cronSecretValidates(cronSecret)) {
      return null;
    }
  }

  // Non-browser client (no cookie, no Origin): nothing to forge.
  if (!cookie && !origin) return null;

  // Trusted hosts (Workers preview URLs) — Origin still checked if present.
  if (isTrustedHost(host) && !origin) return null;

  // Browser-shaped request: Origin is MANDATORY (fail closed).
  if (!origin) {
    return NextResponse.json(
      { error: "CSRF check failed: missing Origin" },
      { status: 403 }
    );
  }

  if (!originMatchesHost(origin, host)) {
    return NextResponse.json(
      { error: "CSRF check failed: origin mismatch" },
      { status: 403 }
    );
  }
  return null;
}
