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
 *  - requests authenticated by a secret header (cron / internal APIs):
 *    x-cron-secret / authorization: Bearer — no browser credentials involved
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
 * CSRF guard. Call at the top of state-changing route handlers.
 *
 * @param req incoming NextRequest
 * @param opts.allowSecretAuth skip the check when the request carries a
 *        valid secret credential (cron/webhook/internal API). Default true —
 *        those callers never carry browser cookies, so CSRF does not apply.
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

  // Secret-authenticated callers (cron, webhooks, internal APIs): no browser
  // credentials are involved, CSRF is not applicable.
  if (opts.allowSecretAuth !== false) {
    const cronSecret = req.headers.get("x-cron-secret");
    const authHeader = req.headers.get("authorization");
    if (cronSecret || (authHeader && authHeader.toLowerCase().startsWith("bearer "))) {
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
