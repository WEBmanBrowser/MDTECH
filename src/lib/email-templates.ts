export function resetRequestEmail(name: string, resetLink: string): { subject: string; html: string } {
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
