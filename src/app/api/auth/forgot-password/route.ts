import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { users } from "@/db/schema";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { issueResetToken } from "@/lib/password-reset";
import { csrfGuard } from "@/lib/csrf";
import { checkRateLimit, rateLimitResponse, rateLimitUnavailableResponse, clientIdentifier } from "@/lib/rate-limit";
import { sendEmail } from "@/lib/email";
import { createAuditLog } from "@/lib/audit";

const forgotSchema = z.object({
  email: z.string().email().max(255),
});

// Generic response returned for every request — prevents email enumeration.
const GENERIC_RESPONSE = {
  message:
    "Se existir uma conta associada a esse email, você receberá um link de redefinição de senha em poucos minutos.",
};

function resetRequestEmail(name: string, resetLink: string): { subject: string; html: string } {
  return {
    subject: "MD Tech — Redefinição de senha",
    html: `<div style="font-family:system-ui;max-width:600px;margin:0 auto;padding:24px">
      <h2 style="color:#0284c7">MD Tech Solutions</h2>
      <p>Olá ${name},</p>
      <p>Recebemos uma solicitação de redefinição de senha para sua conta.</p>
      <p>Clique no link abaixo para definir uma nova senha (válido por 60 minutos):</p>
      <p><a href="${resetLink}">${resetLink}</a></p>
      <p>Se você não solicitou isso, ignore este email — sua senha permanece inalterada.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
      <p style="font-size:12px;color:#64748b">MD Tech Solutions — Esposende, Portugal</p>
    </div>`,
  };
}

export async function POST(req: NextRequest) {
  try {
    const csrf = csrfGuard(req);
    if (csrf) return csrf;

    const rl = await checkRateLimit("forgot_password", clientIdentifier(req));
    if (!rl.allowed) {
      if (rl.infraFailure) {
        const { body, headers } = rateLimitUnavailableResponse();
        return NextResponse.json(body, { status: 503, headers });
      }
      const { body, headers } = rateLimitResponse(rl);
      return NextResponse.json(body, { status: 429, headers });
    }

    const parsed = forgotSchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json(GENERIC_RESPONSE);
    }
    const { email } = parsed.data;

    const [user] = await db
      .select({ id: users.id, name: users.name })
      .from(users)
      .where(eq(users.email, email.toLowerCase().trim()))
      .limit(1);

    if (user) {
      const token = await issueResetToken(user.id);
      const resetLink = `${req.nextUrl.origin}/conta/recuperar-password?token=${token}`;
      const { subject, html } = resetRequestEmail(user.name, resetLink);
      // Never log the token or the link.
      await sendEmail({
        type: "password_reset",
        to: email,
        subject,
        html,
        text: html.replace(/<[^>]+>/g, " "),
      });
      await createAuditLog({
        userId: user.id,
        action: "auth.password_reset_requested",
        entity: "users",
        entityId: user.id,
        ipAddress: clientIdentifier(req),
      });
    }

    // Always the same response regardless of whether the account exists —
    // prevents email enumeration.
    return NextResponse.json(GENERIC_RESPONSE);
  } catch {
    return NextResponse.json(GENERIC_RESPONSE);
  }
}
