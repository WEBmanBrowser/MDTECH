/**
 * P1 — Server-side session revocation.
 *
 * Every JWT embeds the user's tokenVersion at issuance time. Bumping the
 * version in the DB instantly invalidates every previously issued token
 * (logout, password change/reset, account deactivation) — verifyToken
 * rejects any payload whose tokenVersion is older than the user's current
 * one. Works on Cloudflare Workers + PostgreSQL: one atomic UPDATE.
 */
import { db } from "@/db";
import { users } from "@/db/schema";
import { eq, sql } from "drizzle-orm";

/**
 * Bump the user's tokenVersion. All JWTs issued before this call become
 * invalid on the next verifyToken/getCurrentUser call.
 */
export async function revokeUserSessions(userId: number): Promise<void> {
  await db
    .update(users)
    .set({
      tokenVersion: sql`${users.tokenVersion} + 1`,
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId));
}
