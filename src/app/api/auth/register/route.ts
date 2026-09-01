import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { users } from "@/db/schema";
import { z } from "zod";
import { hashPassword, createToken } from "@/lib/auth";
import { csrfGuard } from "@/lib/csrf";
import { checkRateLimit, rateLimitResponse, rateLimitUnavailableResponse, clientIdentifier } from "@/lib/rate-limit";
import { createAuditLog } from "@/lib/audit";

const registerSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(200),
  name: z.string().min(1).max(255),
  phone: z.string().max(50).optional(),
  nif: z.string().max(20).optional(),
});

export async function POST(req: NextRequest) {
  try {
    const csrf = csrfGuard(req);
    if (csrf) return csrf;

    // Rate limit BEFORE touching the users table.
    const rl = await checkRateLimit("register", clientIdentifier(req));
    if (!rl.allowed) {
      if (rl.infraFailure) {
        const { body, headers } = rateLimitUnavailableResponse();
        return NextResponse.json(body, { status: 503, headers });
      }
      const { body, headers } = rateLimitResponse(rl);
      return NextResponse.json(body, { status: 429, headers });
    }

    const parsed = registerSchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json({ error: "Campos obrigatórios em falta" }, { status: 400 });
    }
    const { email, password, name, phone, nif } = parsed.data;

    // P1 anti-enumeration: we do NOT pre-check existence (the old
    // "Email já registado" 409 confirmed the account exists). We just try
    // the insert — the users_email_unique constraint is the race-safe
    // authority. On conflict we return the SAME success-shaped response
    // without a token, so probing reveals nothing.
    const hashed = await hashPassword(password);
    const inserted = await db
      .insert(users)
      .values({
        email,
        password: hashed,
        name,
        phone: phone || null,
        nif: nif || null,
        role: "customer",
      })
      .onConflictDoNothing({ target: users.email })
      .returning();

    if (inserted.length === 0) {
      // Email already exists (or raced). Anti-enumeration: respond like a
      // success but with no session — the real user can just log in.
      await createAuditLog({
        userId: null,
        action: "auth.register_conflict",
        entity: "users",
        ipAddress: clientIdentifier(req),
      });
      return NextResponse.json({
        user: null,
        message: "Se o email não possuir conta, o cadastro foi criado. Verifique seu email ou faça login.",
      });
    }

    const user = inserted[0];
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
      action: "auth.register",
      entity: "users",
      entityId: user.id,
      ipAddress: clientIdentifier(req),
    });
    return response;
  } catch {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}
