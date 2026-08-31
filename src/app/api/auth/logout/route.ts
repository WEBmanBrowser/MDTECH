import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { revokeUserSessions } from "@/lib/session";

export async function POST(req: NextRequest) {
  // P1: logout is now server-side revocation, not just cookie clearing.
  // Bumping tokenVersion invalidates the JWT everywhere it was issued —
  // a stolen/copied cookie dies with the logout.
  try {
    const user = await getCurrentUser();
    if (user) {
      await revokeUserSessions(user.id).catch(() => {});
    }
  } catch {
    // Best-effort revocation; the cookie is cleared regardless.
  }
  const response = NextResponse.json({ ok: true });
  response.cookies.set("auth_token", "", { httpOnly: true, maxAge: 0, path: "/" });
  return response;
}
