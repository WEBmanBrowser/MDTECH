/**
 * P1 — Persistent server-side rate limiting (PostgreSQL/Drizzle).
 *
 * Storage: `rate_limits` table keyed by (bucket, window_start).
 * Increment is ATOMIC: a single INSERT ... ON CONFLICT DO UPDATE adds 1 and
 * returns the new count, so concurrent Workers isolates can never double-count
 * or lose increments — the database serializes them.
 *
 * No in-memory state: safe across Cloudflare Workers isolates and restarts.
 */
import { db } from "@/db";
import { rateLimits } from "@/db/schema";
import { sql } from "drizzle-orm";

export interface RateLimitResult {
  allowed: boolean;
  /** Requests already counted in the current window (including this one). */
  count: number;
  /** Configured max for this window. */
  limit: number;
  /** Seconds until the window rolls over (for Retry-After). */
  retryAfter: number;
  /**
   * True when the limiter itself could not reach the DB. Callers must answer
   * 503 (infrastructure failure) — never 429, which is reserved for an
   * effectively exceeded limit. Fail-CLOSED for auth endpoints: without a
   * working counter we cannot enforce brute-force protection.
   */
  infraFailure?: boolean;
}

export interface RateLimitRule {
  /** Max requests per window. */
  limit: number;
  /** Window length in seconds. */
  windowSeconds: number;
}

/** P1 rules per sensitive endpoint. */
export const RATE_LIMIT_RULES: Record<string, RateLimitRule> = {
  login: { limit: 8, windowSeconds: 60 },
  register: { limit: 4, windowSeconds: 300 },
  forgot_password: { limit: 3, windowSeconds: 300 },
  reset_password: { limit: 6, windowSeconds: 300 },
};

/**
 * Atomic windowed counter.
 *
 * The (bucket, window_start) unique index makes the INSERT ... ON CONFLICT
 * DO UPDATE race-free: two concurrent requests for the same window each run
 * the upsert and the DB applies them sequentially — the returned count is
 * always the true number of requests admitted to this window.
 */
export async function checkRateLimit(
  ruleName: string,
  identifier: string
): Promise<RateLimitResult> {
  const rule = RATE_LIMIT_RULES[ruleName];
  if (!rule) {
    // Unknown rule name — fail open but never crash the endpoint.
    return { allowed: true, count: 0, limit: 0, retryAfter: 0 };
  }

  const bucket = `${ruleName}:${identifier}`;
  const now = Date.now();
  const windowStartMs = now - (now % (rule.windowSeconds * 1000));
  const windowStart = new Date(windowStartMs);
  const retryAfter = Math.max(
    1,
    Math.ceil((windowStartMs + rule.windowSeconds * 1000 - now) / 1000)
  );

  try {
    const rows = await db
      .insert(rateLimits)
      .values({ bucket, windowStart, count: 1 })
      .onConflictDoUpdate({
        target: [rateLimits.bucket, rateLimits.windowStart],
        set: { count: sql`${rateLimits.count} + 1` },
      })
      .returning({ count: rateLimits.count });

    const count = rows[0]?.count ?? 1;
    return {
      allowed: count <= rule.limit,
      count,
      limit: rule.limit,
      retryAfter,
    };
  } catch (e) {
    // Fail-CLOSED: without a working counter we cannot enforce brute-force
    // protection on auth endpoints, so callers must answer 503. Never leak
    // DB details to the client; log the error server-side only.
    console.error("[RATE-LIMIT] backend unavailable, rejecting request", e instanceof Error ? e.message : e);
    return { allowed: false, count: 0, limit: rule.limit, retryAfter, infraFailure: true };
  }
}

/**
 * Build a 429 JSON response with Retry-After.
 * Never echoes the identifier or any request data.
 */
export function rateLimitResponse(result: RateLimitResult): {
  body: Record<string, unknown>;
  headers: Record<string, string>;
} {
  return {
    body: { error: "Muitas tentativas. Tente novamente mais tarde." },
    headers: { "Retry-After": String(result.retryAfter) },
  };
}

/**
 * Build a 503 response for rate-limiter infrastructure failure.
 * Distinct from 429 (limit exceeded): no Retry-After promise, generic body
 * that reveals nothing about the DB.
 */
export function rateLimitUnavailableResponse(): {
  body: Record<string, unknown>;
  headers: Record<string, string>;
} {
  return {
    body: { error: "Serviço temporariamente indisponível. Tente novamente em instantes." },
    headers: { "Retry-After": "30" },
  };
}

/** Best-effort client identifier: forwarded IP > remote IP > "anon". */
export function clientIdentifier(req: Request): string {
  const fwd = req.headers.get("cf-connecting-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("x-real-ip")
    || "anon";
  return fwd.slice(0, 200);
}
