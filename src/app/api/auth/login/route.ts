import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { users } from "@/db/schema";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { verifyPassword, createToken } from "@/lib/auth";
import { csrfGuard } from "@/lib/csrf";
import { checkRateLimit, rateLimitResponse, clientIdentifier } from "@/lib/rate-limit";
import { invalidateUserResetTokens } from "@/lib/password-reset";
import { createAuditLog } from "@/lib/audit";

const loginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(1).max(200),
});

export async function POST(req: NextRequest) {
  try {
    const csrf = csrfGuard(req);
    if (csrf) return csrf;

    // Rate limit BEFORE touching the users table (anti brute-force + timing).
    const rl = await checkRateLimit("login", clientIdentifier(req));
    if (!rl.allowed) {
      const { body, headers } = rateLimitResponse(rl);
      return NextResponse.json(body, { status: 429, headers });
    }

    const parsed = loginSchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json({ error: "Email e password são obrigatórios" }, { status: 400 });
    }
    const { email, password } = parsed.data;

    const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    if (!user || !user.isActive) {
      return NextResponse.json({ error: "Credenciais inválidas" }, { status: 401 });
    }
    const valid = await verifyPassword(password, user.password);
    if (!valid) {
      return NextResponse.json({ error: "Credenciais inválidas" }, { status: 401 });
    }

    // Fresh login invalidates any outstanding reset tokens.
    await invalidateUserResetTokens(user.id).catch(() => {});

    const token = createToken({ userId: user.id, role: user.role, tokenVersion: user.tokenVersion ?? 0 });
    const response = NextResponse.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
    });
    response.cookies.set("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60,
      path: "/",
    });

    await createAuditLog({
      userId: user.id,
      action: "auth.login",
      entity: "users",
      entityId: user.id,
      ipAddress: clientIdentifier(req),
    });
    return response;
  } catch {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}
