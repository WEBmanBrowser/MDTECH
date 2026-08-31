"use client";
import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";

export default function RecuperarPasswordClient() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") || "";

  const [email, setEmail] = useState("");
  const [requesting, setRequesting] = useState(false);
  const [requestDone, setRequestDone] = useState(false);

  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [resetting, setResetting] = useState(false);
  const [error, setError] = useState("");
  const [resetOk, setResetOk] = useState(false);

  useEffect(() => {
    // Clear stale validation errors when the token changes. Deferred so the
    // effect doesn't trigger a cascading render during the initial commit.
    const t = setTimeout(() => setError(""), 0);
    return () => clearTimeout(t);
  }, [token]);

  const requestReset = async () => {
    setError("");
    if (!email.trim()) { setError("Digite seu email."); return; }
    setRequesting(true);
    try {
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      // Anti-enumeration: the response is identical whether or not the
      // account exists — always show the same confirmation.
      if (res.ok || res.status === 429) {
        setRequestDone(true);
      } else {
        setRequestDone(true);
      }
    } catch {
      setRequestDone(true);
    } finally {
      setRequesting(false);
    }
  };

  const doReset = async () => {
    setError("");
    if (password.length < 8) { setError("A senha precisa ter ao menos 8 caracteres."); return; }
    if (password !== password2) { setError("As senhas não coincidem."); return; }
    setResetting(true);
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setResetOk(true);
        setTimeout(() => router.push("/conta?tab=login"), 1800);
      } else {
        setError(data.error || "Token inválido, expirado ou já utilizado.");
      }
    } catch {
      setError("Erro de rede. Tente novamente.");
    } finally {
      setResetting(false);
    }
  };

  if (resetOk) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 max-w-md w-full text-center">
          <div className="text-4xl mb-3">✅</div>
          <h1 className="text-xl font-bold text-white mb-2">Senha alterada!</h1>
          <p className="text-sm text-slate-400 mb-4">Sua senha foi redefinida. Todas as sessões antigas foram encerradas.</p>
          <Link href="/conta?tab=login" className="inline-block px-5 py-2.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-sm font-semibold transition">Entrar</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 max-w-md w-full">
        <Link href="/" className="flex items-center gap-2 mb-6">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-lime-400 to-sky-500 flex items-center justify-center font-black text-white text-xs">MD</div>
          <span className="text-white font-bold">MDTech Solutions</span>
        </Link>

        {!token ? (
          <>
            <h1 className="text-xl font-bold text-white mb-1">Recuperar senha</h1>
            <p className="text-sm text-slate-400 mb-5">Digite seu email e enviaremos um link de redefinição.</p>
            {requestDone ? (
              <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4 text-sm text-slate-300">
                Se existir uma conta para <span className="text-white">{email}</span>, você receberá
                um email com o link de redefinição em poucos minutos. Verifique também a caixa de spam.
              </div>
            ) : (
              <div className="space-y-3">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="seu@email.pt"
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:border-sky-500 focus:outline-none"
                  onKeyDown={(e) => e.key === "Enter" && requestReset()}
                />
                {error && <p className="text-sm text-red-400">{error}</p>}
                <button
                  onClick={requestReset}
                  disabled={requesting}
                  className="w-full py-2.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg text-sm font-semibold transition"
                >
                  {requesting ? "Enviando..." : "Enviar link de redefinição"}
                </button>
                <Link href="/conta?tab=login" className="block text-center text-xs text-slate-500 hover:text-slate-300">Voltar ao login</Link>
              </div>
            )}
          </>
        ) : (
          <>
            <h1 className="text-xl font-bold text-white mb-1">Definir nova senha</h1>
            <p className="text-sm text-slate-400 mb-5">Escolha uma nova senha para sua conta.</p>
            <div className="space-y-3">
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Nova senha (mín. 8 caracteres)"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:border-sky-500 focus:outline-none"
              />
              <input
                type="password"
                value={password2}
                onChange={(e) => setPassword2(e.target.value)}
                placeholder="Confirmar nova senha"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:border-sky-500 focus:outline-none"
              />
              {error && <p className="text-sm text-red-400">{error}</p>}
              <button
                onClick={doReset}
                disabled={resetting}
                className="w-full py-2.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg text-sm font-semibold transition"
              >
                {resetting ? "Salvando..." : "Redefinir senha"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
