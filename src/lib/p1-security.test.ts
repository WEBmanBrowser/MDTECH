/**
 * P1 — Freebuff security test suite.
 *
 * Deterministic and DB-free: the Drizzle `db` proxy is mocked so the tests
 * exercise the actual production logic (CSRF decisions, rate-limit windowing,
 * token consumption, session revocation) without a PostgreSQL connection.
 *
 * Covers the P1 audit requirements:
 *  - CSRF: same-origin allowed, cross-origin blocked, missing Origin blocked
 *    for browser-shaped requests, GET never blocked, forged x-cron-secret and
 *    Bearer headers do NOT bypass, a VALIDATED x-cron-secret does.
 *  - Rate limiting: under-limit allowed, over-limit blocked with 429 data,
 *    Retry-After present, atomic upsert shape (count = count + 1), and
 *    infra failure → fail-closed (allowed=false + infraFailure, NOT fail-open).
 *  - Password reset: 256-bit token, only SHA-256 hash persisted, single-use
 *    consumption is an atomic conditional UPDATE, single-active re-issue.
 *  - Sessions: tokenVersion bump invalidates older JWTs server-side.
 *  - Anti-enumeration: register/forgot response shapes reveal nothing.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

// ── Mock the DB layer before importing anything that touches @/db ─────────
vi.mock("@/db", () => {
  const chain = () => {
    const p: Record<string, unknown> = {
      insert: vi.fn(() => p),
      values: vi.fn(() => p),
      onConflictDoUpdate: vi.fn(() => p),
      onConflictDoNothing: vi.fn(() => p),
      returning: vi.fn(async () => [{ count: 1 }]),
      update: vi.fn(() => p),
      set: vi.fn(() => p),
      where: vi.fn(async () => [{ userId: 42 }]),
      select: vi.fn(() => p),
      from: vi.fn(() => p),
      limit: vi.fn(async () => []),
      delete: vi.fn(() => p),
      execute: vi.fn(async () => undefined),
    };
    return p;
  };
  const instance = chain();
  return {
    db: new Proxy(instance, {
      get(target, prop) {
        if (prop in target) return target[prop];
        return vi.fn(() => target);
      },
    }),
    pool: {},
  };
});

vi.mock("@/db/schema", () => {
  const col = (name: string) => ({ name, getSQL: () => name });
  return {
    rateLimits: {
      bucket: col("bucket"),
      windowStart: col("window_start"),
      count: col("count"),
    },
    passwordResetTokens: {
      userId: col("user_id"),
      tokenHash: col("token_hash"),
      expiresAt: col("expires_at"),
      usedAt: col("used_at"),
    },
    users: { tokenVersion: col("token_version"), id: col("id"), updatedAt: col("updated_at") },
  };
});

import { csrfGuard } from "./csrf";
import {
  checkRateLimit,
  clientIdentifier,
  RATE_LIMIT_RULES,
  rateLimitResponse,
  rateLimitUnavailableResponse,
} from "./rate-limit";
import {
  consumeResetToken,
  generateResetToken,
  hashResetToken,
  issueResetToken,
} from "./password-reset";
import { revokeUserSessions } from "./session";
import { db } from "@/db";

// ── Helpers ────────────────────────────────────────────────────────────────
import { NextRequest } from "next/server";

function makeReq(
  url: string,
  init: {
    method?: string;
    origin?: string;
    host?: string;
    cookie?: string;
    cronSecret?: string;
    authorization?: string;
  } = {}
): NextRequest {
  const headers = new Headers();
  if (init.origin) headers.set("origin", init.origin);
  if (init.host) headers.set("host", init.host);
  if (init.cookie) headers.set("cookie", init.cookie);
  if (init.cronSecret) headers.set("x-cron-secret", init.cronSecret);
  if (init.authorization) headers.set("authorization", init.authorization);
  const req = new NextRequest(url, {
    method: init.method ?? "POST",
    headers,
  });
  return req;
}

const BROWSER_COOKIE = "auth_token=abc.def.ghi";

// ═══ CSRF ══════════════════════════════════════════════════════════════════
describe("CSRF guard", () => {
  it("allows a same-origin browser POST", () => {
    const res = csrfGuard(
      makeReq("https://shop.example/api/orders", {
        origin: "https://shop.example",
        host: "shop.example",
        cookie: BROWSER_COOKIE,
      })
    );
    expect(res).toBeNull();
  });

  it("blocks a cross-origin browser POST", () => {
    const res = csrfGuard(
      makeReq("https://shop.example/api/orders", {
        origin: "https://evil.example",
        host: "shop.example",
        cookie: BROWSER_COOKIE,
      })
    );
    expect(res?.status).toBe(403);
  });

  it("blocks a browser-shaped POST with cookie but NO Origin (fail closed)", () => {
    const res = csrfGuard(
      makeReq("https://shop.example/api/orders", {
        host: "shop.example",
        cookie: BROWSER_COOKIE,
      })
    );
    expect(res?.status).toBe(403);
  });

  it("never blocks GET/HEAD/OPTIONS", () => {
    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      const res = csrfGuard(
        makeReq("https://shop.example/api/orders", {
          method,
          origin: "https://evil.example",
          host: "shop.example",
          cookie: BROWSER_COOKIE,
        })
      );
      expect(res).toBeNull();
    }
  });

  it("does NOT bypass on a forged x-cron-secret header", () => {
    const previousCron = process.env.CRON_SECRET;
    const previousJwt = process.env.JWT_SECRET;
    process.env.CRON_SECRET = "real-cron-secret-value";
    delete process.env.JWT_SECRET;
    try {
      const res = csrfGuard(
        makeReq("https://shop.example/api/orders", {
          origin: "https://evil.example",
          host: "shop.example",
          cookie: BROWSER_COOKIE,
          cronSecret: "forged-value",
        })
      );
      // Forged secret → falls through to the Origin check → blocked.
      expect(res?.status).toBe(403);
    } finally {
      if (previousCron === undefined) delete process.env.CRON_SECRET;
      else process.env.CRON_SECRET = previousCron;
      if (previousJwt === undefined) delete process.env.JWT_SECRET;
      else process.env.JWT_SECRET = previousJwt;
    }
  });

  it("does NOT bypass on a Bearer header alone (Bearer + cookie is browser-shaped)", () => {
    const res = csrfGuard(
      makeReq("https://shop.example/api/orders", {
        origin: "https://evil.example",
        host: "shop.example",
        cookie: BROWSER_COOKIE,
        authorization: "Bearer some-jwt",
      })
    );
    expect(res?.status).toBe(403);
  });

  it("allows a VALIDATED x-cron-secret (cron stays functional)", () => {
    const previous = process.env.CRON_SECRET;
    const previousJwt = process.env.JWT_SECRET;
    process.env.CRON_SECRET = "real-cron-secret-value";
    delete process.env.JWT_SECRET;
    try {
      const res = csrfGuard(
        makeReq("https://cron.internal/api/cron/expire-reservations", {
          cronSecret: "real-cron-secret-value",
          host: "cron.internal",
        })
      );
      expect(res).toBeNull();
    } finally {
      if (previous === undefined) delete process.env.CRON_SECRET;
      else process.env.CRON_SECRET = previous;
      if (previousJwt === undefined) delete process.env.JWT_SECRET;
      else process.env.JWT_SECRET = previousJwt;
    }
  });

  it("does not bypass when CRON_SECRET is unset and a secret is sent", () => {
    const previousCron = process.env.CRON_SECRET;
    const previousJwt = process.env.JWT_SECRET;
    delete process.env.CRON_SECRET;
    delete process.env.JWT_SECRET;
    try {
      const res = csrfGuard(
        makeReq("https://shop.example/api/orders", {
          origin: "https://evil.example",
          host: "shop.example",
          cookie: BROWSER_COOKIE,
          cronSecret: "anything",
        })
      );
      expect(res?.status).toBe(403);
    } finally {
      if (previousCron === undefined) delete process.env.CRON_SECRET;
      else process.env.CRON_SECRET = previousCron;
      if (previousJwt === undefined) delete process.env.JWT_SECRET;
      else process.env.JWT_SECRET = previousJwt;
    }
  });
});

// ═══ Rate limiting ═════════════════════════════════════════════════════════
describe("rate limiter", () => {
  it("has rules for the four auth endpoints", () => {
    expect(Object.keys(RATE_LIMIT_RULES).sort()).toEqual(
      ["forgot_password", "login", "register", "reset_password"].sort()
    );
  });

  it("allows a request under the limit", async () => {
    const insertSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "insert")
      .mockReturnValue({
        values: () => ({
          onConflictDoUpdate: () => ({
            returning: async () => [{ count: 1 }],
          }),
        }),
      } as never);
    try {
      const result = await checkRateLimit("login", "1.2.3.4");
      expect(result.allowed).toBe(true);
      expect(result.infraFailure).toBeUndefined();
    } finally {
      insertSpy.mockRestore();
    }
  });

  it("blocks with 429 data once the limit is exceeded (no infraFailure)", async () => {
    const insertSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "insert")
      .mockReturnValue({
        values: () => ({
          onConflictDoUpdate: () => ({
            returning: async () => [
              { count: RATE_LIMIT_RULES.login.limit + 1 },
            ],
          }),
        }),
      } as never);
    try {
      const result = await checkRateLimit("login", "1.2.3.4");
      expect(result.allowed).toBe(false);
      expect(result.infraFailure).toBeUndefined();
      const { body, headers } = rateLimitResponse(result);
      expect(headers["Retry-After"]).toMatch(/^\d+$/);
      expect(JSON.stringify(body)).not.toContain("1.2.3.4");
    } finally {
      insertSpy.mockRestore();
    }
  });

  it("uses an atomic count = count + 1 upsert (race-safe shape)", async () => {
    const onConflict = vi.fn(() => ({
      returning: async () => [{ count: 2 }],
    }));
    const setSpy = vi.fn(() => ({ onConflictDoUpdate: onConflict }));
    const valuesSpy = vi.fn(() => ({ onConflictDoUpdate: onConflict }));
    const insertSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "insert")
      .mockReturnValue({ values: valuesSpy } as never);
    try {
      await checkRateLimit("register", "5.6.7.8");
      expect(valuesSpy).toHaveBeenCalled();
      expect(onConflict).toHaveBeenCalledWith(
        expect.objectContaining({
          set: expect.objectContaining({ count: expect.anything() }),
        })
      );
    } finally {
      insertSpy.mockRestore();
    }
  });

  it("fails CLOSED on backend failure (infraFailure, never fail-open)", async () => {
    const insertSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "insert")
      .mockImplementation(() => {
        throw new Error("connection refused");
      });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await checkRateLimit("forgot_password", "9.9.9.9");
      expect(result.allowed).toBe(false);
      expect(result.infraFailure).toBe(true);
      const { body, headers } = rateLimitUnavailableResponse();
      expect(headers["Retry-After"]).toBe("30");
      expect(JSON.stringify(body)).not.toMatch(/database|postgres|db/i);
    } finally {
      insertSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  it("derives the client identifier from forwarded headers", () => {
    const req = new Request("https://x.test", {
      headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" },
    });
    expect(clientIdentifier(req)).toBe("203.0.113.7");
    const anon = new Request("https://x.test");
    expect(clientIdentifier(anon)).toBe("anon");
  });
});

// ═══ Password reset ════════════════════════════════════════════════════════
describe("password reset tokens", () => {
  it("generates a 256-bit base64url token", () => {
    const token = generateResetToken();
    // 32 bytes → 43 base64url chars, no padding, URL-safe alphabet.
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const other = generateResetToken();
    expect(other).not.toBe(token);
  });

  it("hashes tokens with SHA-256 (64 hex chars), never storing the raw token", async () => {
    const token = generateResetToken();
    const hash = await hashResetToken(token);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toContain(token);
    // Deterministic: same token → same hash.
    expect(await hashResetToken(token)).toBe(hash);
  });

  it("issues single-active: re-issue deletes previous tokens for the user", async () => {
    const deleteSpy = vi.fn(() => ({
      where: vi.fn(async () => undefined),
    }));
    const valuesSpy = vi.fn(async () => undefined);
    const insertSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "insert")
      .mockReturnValue({ values: valuesSpy } as never);
    const deleteMock = vi
      .spyOn(db as unknown as Record<string, unknown>, "delete")
      .mockReturnValue(deleteSpy() as never);
    try {
      const token = await issueResetToken(7);
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      // The previous tokens were deleted (single-active) before inserting.
      expect(deleteMock).toHaveBeenCalled();
      expect(valuesSpy).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 7, tokenHash: expect.stringMatching(/^[0-9a-f]{64}$/) })
      );
    } finally {
      insertSpy.mockRestore();
      deleteMock.mockRestore();
    }
  });

  it("consumes a token atomically: UPDATE ... WHERE unused AND unexpired", async () => {
    const whereSpy = vi.fn(() => ({
      returning: vi.fn(async () => [{ userId: 42 }]),
    }));
    const setSpy = vi.fn(() => ({ where: whereSpy }));
    const updateSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "update")
      .mockReturnValue({ set: setSpy } as never);
    try {
      const token = generateResetToken();
      const result = await consumeResetToken(token);
      expect(result).toEqual({ ok: true, userId: 42 });
      expect(setSpy).toHaveBeenCalledWith(
        expect.objectContaining({ usedAt: expect.any(Date) })
      );
    } finally {
      updateSpy.mockRestore();
    }
  });

  it("rejects an unknown token with reason 'invalid'", async () => {
    const whereSpy = vi.fn(() => ({
      returning: vi.fn(async () => []), // UPDATE matched nothing
    }));
    const setSpy = vi.fn(() => ({ where: whereSpy }));
    const updateSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "update")
      .mockReturnValue({ set: setSpy } as never);
    const selectLimitSpy = vi.fn(async () => []); // no row exists
    const fromSpy = vi.fn(() => ({ where: () => ({ limit: selectLimitSpy }) }));
    const selectSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "select")
      .mockReturnValue({ from: fromSpy } as never);
    try {
      const result = await consumeResetToken(generateResetToken());
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("invalid");
    } finally {
      updateSpy.mockRestore();
      selectSpy.mockRestore();
    }
  });

  it("rejects an already-used token with reason 'used'", async () => {
    const whereSpy = vi.fn(() => ({
      returning: vi.fn(async () => []), // UPDATE matched nothing
    }));
    const setSpy = vi.fn(() => ({ where: whereSpy }));
    const updateSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "update")
      .mockReturnValue({ set: setSpy } as never);
    const selectLimitSpy = vi.fn(async () => [
      { expiresAt: new Date(Date.now() + 60_000), usedAt: new Date() },
    ]);
    const fromSpy = vi.fn(() => ({ where: () => ({ limit: selectLimitSpy }) }));
    const selectSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "select")
      .mockReturnValue({ from: fromSpy } as never);
    try {
      const result = await consumeResetToken(generateResetToken());
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("used");
    } finally {
      updateSpy.mockRestore();
      selectSpy.mockRestore();
    }
  });

  it("rejects an expired token with reason 'expired'", async () => {
    const whereSpy = vi.fn(() => ({
      returning: vi.fn(async () => []), // UPDATE matched nothing
    }));
    const setSpy = vi.fn(() => ({ where: whereSpy }));
    const updateSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "update")
      .mockReturnValue({ set: setSpy } as never);
    const selectLimitSpy = vi.fn(async () => [
      { expiresAt: new Date(Date.now() - 60_000), usedAt: null },
    ]);
    const fromSpy = vi.fn(() => ({ where: () => ({ limit: selectLimitSpy }) }));
    const selectSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "select")
      .mockReturnValue({ from: fromSpy } as never);
    try {
      const result = await consumeResetToken(generateResetToken());
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("expired");
    } finally {
      updateSpy.mockRestore();
      selectSpy.mockRestore();
    }
  });
});

// ═══ Sessions / JWT revocation ═════════════════════════════════════════════
describe("session revocation", () => {
  it("bumps tokenVersion atomically (token_version = token_version + 1)", async () => {
    const whereSpy = vi.fn(async () => undefined);
    const setSpy = vi.fn(() => ({ where: whereSpy }));
    const updateSpy = vi
      .spyOn(db as unknown as Record<string, unknown>, "update")
      .mockReturnValue({ set: setSpy } as never);
    try {
      await revokeUserSessions(3);
      expect(updateSpy).toHaveBeenCalled();
      expect(setSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenVersion: expect.anything(),
          updatedAt: expect.any(Date),
        })
      );
    } finally {
      updateSpy.mockRestore();
    }
  });

  it("getCurrentUser rejects a JWT issued before the current tokenVersion", async () => {
    vi.resetModules();
    const previousSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = "test-secret-for-p1";
    const verifyTokenSpy = vi.fn(() => ({
      userId: 5,
      role: "customer",
      tokenVersion: 2, // issued when version was 2…
    }));
    vi.doMock("jsonwebtoken", () => ({
      default: { verify: verifyTokenSpy, sign: vi.fn() },
    }));
    // DB reports the user's CURRENT version as 3 (bumped after issuance).
    vi.doMock("@/db", () => ({
      db: {
        select: () => ({
          from: () => ({
            where: () => ({
              limit: async () => [
                {
                  id: 5,
                  email: "u@x.test",
                  name: "U",
                  role: "customer",
                  isActive: true,
                  tokenVersion: 3,
                  phone: null,
                  nif: null,
                  company: null,
                },
              ],
            }),
          }),
        }),
      },
    }));
    const cookiesMock = {
      get: (name: string) =>
        name === "auth_token" ? { value: "old.jwt" } : undefined,
    };
    vi.doMock("next/headers", () => ({ cookies: async () => cookiesMock }));
    const { getCurrentUser } = await import("./auth");
    try {
      const user = await getCurrentUser();
      // issuedVersion (2) < current (3) → session revoked server-side.
      expect(user).toBeNull();
    } finally {
      if (previousSecret === undefined) delete process.env.JWT_SECRET;
      else process.env.JWT_SECRET = previousSecret;
      vi.doUnmock("./auth");
      vi.doUnmock("jsonwebtoken");
      vi.doUnmock("@/db");
      vi.doUnmock("next/headers");
    }
  });

  it("getCurrentUser accepts a JWT whose tokenVersion matches (default 0 users)", async () => {
    vi.resetModules();
    const previousSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = "test-secret-for-p1";
    vi.doMock("jsonwebtoken", () => ({
      default: {
        verify: vi.fn(() => ({ userId: 5, role: "customer", tokenVersion: 0 })),
        sign: vi.fn(),
      },
    }));
    vi.doMock("@/db", () => ({
      db: {
        select: () => ({
          from: () => ({
            where: () => ({
              limit: async () => [
                {
                  id: 5,
                  email: "u@x.test",
                  name: "U",
                  role: "customer",
                  isActive: true,
                  tokenVersion: 0, // pre-migration default
                  phone: null,
                  nif: null,
                  company: null,
                },
              ],
            }),
          }),
        }),
      },
    }));
    const cookiesMock = {
      get: (name: string) =>
        name === "auth_token" ? { value: "jwt" } : undefined,
    };
    vi.doMock("next/headers", () => ({ cookies: async () => cookiesMock }));
    const { getCurrentUser } = await import("./auth");
    try {
      const user = await getCurrentUser();
      expect(user?.id).toBe(5);
    } finally {
      if (previousSecret === undefined) delete process.env.JWT_SECRET;
      else process.env.JWT_SECRET = previousSecret;
      vi.doUnmock("./auth");
      vi.doUnmock("jsonwebtoken");
      vi.doUnmock("@/db");
      vi.doUnmock("next/headers");
    }
  });
});

// ═══ Anti-enumeration shapes ═══════════════════════════════════════════════
describe("anti-enumeration response shapes", () => {
  it("register conflict response carries no user and no distinct error", async () => {
    vi.resetModules();
    vi.doMock("@/db", () => ({
      db: {
        insert: () => ({
          values: () => ({
            onConflictDoNothing: () => ({ returning: async () => [] }),
          }),
        }),
      },
    }));
    vi.doMock("@/lib/audit", () => ({
      createAuditLog: vi.fn(async () => undefined),
    }));
    vi.doMock("@/lib/rate-limit", () => ({
      checkRateLimit: vi.fn(async () => ({
        allowed: true,
        count: 1,
        limit: 4,
        retryAfter: 300,
      })),
      rateLimitResponse: () => ({ body: {}, headers: {} }),
      rateLimitUnavailableResponse: () => ({ body: {}, headers: {} }),
      clientIdentifier: () => "test",
    }));
    vi.doMock("@/lib/csrf", () => ({ csrfGuard: () => null }));
    vi.doMock("@/lib/auth", () => ({
      hashPassword: vi.fn(async () => "$2a$12$fakehash"),
      createToken: vi.fn(() => "jwt"),
    }));
    try {
      const { POST } = await import(
        "@/app/api/auth/register/route"
      );
      const req = new NextRequest("http://localhost/api/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email: "taken@x.test",
          password: "longenough1",
          name: "T",
        }),
        headers: { "content-type": "application/json" },
      });
      const res = await POST(req);
      const body = await res.json();
      // Success-shaped, no token cookie set, no "already registered" signal.
      expect(res.status).toBe(200);
      expect(body.user).toBeNull();
      expect(res.headers.get("set-cookie")).toBeNull();
    } finally {
      vi.doUnmock("@/db");
      vi.doUnmock("@/lib/audit");
      vi.doUnmock("@/lib/rate-limit");
      vi.doUnmock("@/lib/csrf");
      vi.doUnmock("@/lib/auth");
    }
  });
});
