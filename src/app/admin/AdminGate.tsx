import { getCurrentUser, hasRole, UserRole } from "@/lib/auth";

/**
 * P1 — Server-side admin gate.
 *
 * The old layout only redirected client-side (after the page had already
 * rendered in the browser). This server component checks the session and
 * RBAC BEFORE any admin content is rendered or shipped to the client.
 */
export default async function AdminGate({ children }: { children: React.ReactNode }) {
  const user = await getCurrentUser();
  if (!user || !hasRole(user.role, "staff" as UserRole)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 max-w-md w-full text-center">
          <div className="text-4xl mb-3">🔒</div>
          <h1 className="text-xl font-bold text-white mb-2">Acesso restrito</h1>
          <p className="text-sm text-slate-400 mb-5">
            Esta área requer uma sessão de staff e não está disponível para sua conta.
          </p>
          <a href="/conta?tab=login" className="inline-block px-5 py-2.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-sm font-semibold transition">
            Entrar
          </a>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}
