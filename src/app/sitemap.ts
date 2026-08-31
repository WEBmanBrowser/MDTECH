import type { MetadataRoute } from "next";

/**
 * P1 — sitemap with only public, indexable pages.
 * Private/transactional routes (/admin, /conta, /checkout, /api) are excluded
 * here AND disallowed in robots.ts.
 */
export default function sitemap(): MetadataRoute.Sitemap {
  // Base URL: override with NEXT_PUBLIC_SITE_URL in production.
  const base = (process.env.NEXT_PUBLIC_SITE_URL || "https://mdtechsolutions.pt")
    .replace(/\/$/, "");

  const staticPages: MetadataRoute.Sitemap = [
    "",
    "/produtos",
    "/carrinho",
    "/comparador",
    "/configurador",
    "/smart-shopping",
  ].map((path) => ({
    url: `${base}${path}`,
    lastModified: new Date(),
    changeFrequency: "daily" as const,
    priority: path === "" ? 1 : 0.8,
  }));

  return staticPages;
}
