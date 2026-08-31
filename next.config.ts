import type { NextConfig } from "next";

const isProd = process.env.NODE_ENV === "production";

// P1 security headers. CSP is intentionally permissive enough for Next.js
// inline bootstrapping scripts (unsafe-inline for script-src is required by
// Next.js App Router hydration) while locking down framing, sniffing and
// referrer leakage.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      // Next.js App Router requires inline/eval for hydration bootstrapping.
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "font-src 'self' data:",
      "connect-src 'self' https:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
  // HSTS only makes sense over HTTPS in production.
  ...(isProd ? [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" }] : []),
];

const nextConfig: NextConfig = {
  // Image optimization: use 'custom' loader for Cloudflare Workers compatibility
  // (Cloudflare does not support Next.js default image optimization out of the box)
  images: {
    unoptimized: true,
  },
  // Required so OpenNext copies the full pg-cloudflare package (including workerd condition files)
  serverExternalPackages: ["pg-cloudflare"],
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
