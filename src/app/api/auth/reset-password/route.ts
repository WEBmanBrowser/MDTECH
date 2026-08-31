import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { users } from "@/db/schema";
import { eq, sql } from "drizzle-orm";
import { z } from "zod";
import { consumeResetToken } from "@/lib/password-reset";
import { hashPassword } from "@/lib/auth";
import { revokeUserSessions } from "@/lib/session";
import { csrfGuard } from "@/lib/csrf";
import { checkRateLimit, rateLimitResponse, clientIdentifier } from "@/lib/rate-limit";
import { createAuditLog } from "@/lib/audit";

const resetSchema = z.object({
  token: z.string().min(20).max(200),
  password: z.string().min(8).max(200),
});

export async function POST(req: NextRequest) {
  try {
    const csrf = csrfGuard(req);
    if (csrf) return csrf;

    const rl = await checkRateLimit("reset_password", clientIdentifier(req));
    if (!rl.allowed) {
      const { body, headers } = rateLimitResponse(rl);
      return NextResponse.json(body, { status: 429, headers });
    }

    const parsed = resetSchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Token ou senha inválidos (senha precisa ter ao menos 8 caracteres)." },
        { status: 400 }
      );
    }
    const { token, password } = parsed.data;

    // Atomic single-use consumption (UPDATE ... WHERE used_at IS NULL AND
    // expires_at > now()) — exactly one concurrent caller wins.
    const result = await consumeResetToken(token);
    if (!result.ok || result.userId === null) {
      return NextResponse.json(
        { error: "Token inválido, expirado ou já utilizado. Solicite um novo link." },
        { status: 400 }
      );
    }

    const hashed = await hashPassword(password);
    await db
      .update(users)
      .set({ password: hashed, tokenVersion: sql`token_version + 1`, updatedAt: new Date() })
      .where(eq(users.id, result.userId));

    // Password changed: every previously issued JWT is now invalid.
    await revokeUserSessions(result.userId).catch(() => {});

    await createAuditLog({
      userId: result.userId,
      action: "auth.password_reset_completed",
      entity: "users",
      entityId: result.userId,
      ipAddress: clientIdentifier(req),
    });

    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json(
      { error: "Erro interno. Tente novamente." },
      { status: 500 }
    );
  }
}
