/**
 * P1 — Secure password reset tokens.
 *
 * - Token: 32 bytes from crypto.getRandomValues → 43-char base64url (~256 bits).
 * - Storage: SHA-256 hash ONLY (the token itself is never persisted).
 * - TTL: 60 minutes max.
 * - Single-use: consumed atomically via UPDATE ... WHERE used_at IS NULL AND
 *   expires_at > now() — exactly one concurrent caller wins.
 * - Single-active: issuing a new token deletes all previous ones for the user.
 * - Anti-enumeration: callers return the same response whether or not the
 *   email exists; the token never appears in logs or audit records.
 */
import { db } from "@/db";
import { passwordResetTokens } from "@/db/schema";
import { and, eq, isNull, sql } from "drizzle-orm";

const TOKEN_TTL_MS = 60 * 60 * 1000; // 60 minutes
const TOKEN_BYTES = 32; // 256 bits

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateResetToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

export async function hashResetToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Issue a reset token for a user. Deletes all previous tokens first
 * (single-active guarantee). Returns the plaintext token — the caller
 * embeds it in the email link and must never log it.
 */
export async function issueResetToken(userId: number): Promise<string> {
  const token = generateResetToken();
  const tokenHash = await hashResetToken(token);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 60 minutes

  // Single-active: invalidate any previous tokens for this user.
  await db.delete(passwordResetTokens).where(eq(passwordResetTokens.userId, userId));
  await db.insert(passwordResetTokens).values({ userId, tokenHash, expiresAt });
  return token;
}

export interface ConsumeResult {
  ok: boolean;
  userId: number | null;
  /** "expired" | "used" | "invalid" — for audit only, never surfaced to users. */
  reason?: string;
}

/**
 * Atomically consume a reset token. Exactly one concurrent caller wins:
 * the UPDATE matches only when the token is unexpired AND unused, and the
 * row lock serializes concurrent consumers.
 */
export async function consumeResetToken(token: string): Promise<{
  ok: boolean;
  userId: number | null;
  reason?: string;
}> {
  const tokenHash = await hashResetToken(token);
  const now = new Date();

  const rows = await db
    .update(passwordResetTokens)
    .set({ usedAt: now })
    .where(
      sql`${passwordResetTokens.tokenHash} = ${tokenHash}
          AND ${passwordResetTokens.usedAt} IS NULL
          AND ${passwordResetTokens.expiresAt} > ${now.toISOString()}`
    )
    .returning({ userId: passwordResetTokens.userId });

  if (rows.length > 0) {
    return { ok: true, userId: rows[0].userId };
  }

  // Distinguish reason for audit only — never surfaced to the user.
  const [row] = await db
    .select({ expiresAt: passwordResetTokens.expiresAt, usedAt: passwordResetTokens.usedAt })
    .from(passwordResetTokens)
    .where(eq(passwordResetTokens.tokenHash, tokenHash))
    .limit(1);
  if (!row) return { ok: false, userId: null, reason: "invalid" };
  if (row.usedAt) return { ok: false, userId: null, reason: "used" };
  return { ok: false, userId: null, reason: "expired" };
}

/** Invalidate any outstanding tokens for a user (e.g. after a fresh login). */
export async function invalidateUserResetTokens(userId: number): Promise<void> {
  await db.delete(passwordResetTokens).where(eq(passwordResetTokens.userId, userId));
}
