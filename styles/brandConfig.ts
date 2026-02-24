// ─────────────────────────────────────────────────────────────
// Brand Configuration — Central brand identity file
// ─────────────────────────────────────────────────────────────

import { BrandConfig } from "../transform/brandingEngine";

/**
 * FTH (From The Hart) — Primary brand configuration.
 */
export const FTH_BRAND: BrandConfig = {
  name: "From The Hart",
  colors: {
    primary: "#1a1a2e",
    secondary: "#16213e",
    accent: "#e94560",
    background: "#ffffff",
    text: "#1a1a1a",
  },
  fonts: {
    heading: "'Montserrat', 'Segoe UI', sans-serif",
    body: "'Open Sans', 'Segoe UI', sans-serif",
    mono: "'Fira Code', 'Consolas', monospace",
  },
  logo: {
    url: "",
    width: "140px",
    height: "auto",
    position: "left",
  },
  header: {
    text: "From The Hart",
    tagline: "Infrastructure for the Future of Decentralized Governance",
  },
  footer: {
    text: "© From The Hart — All Rights Reserved",
    website: "https://fromthehart.io",
  },
  borders: {
    radius: "8px",
    width: "1px",
    color: "#e2e8f0",
  },
};

/**
 * Clean professional brand — minimal styling.
 */
export const CLEAN_BRAND: BrandConfig = {
  name: "Professional",
  colors: {
    primary: "#111827",
    secondary: "#374151",
    accent: "#2563eb",
    background: "#ffffff",
    text: "#1f2937",
  },
  fonts: {
    heading: "'Georgia', serif",
    body: "'Segoe UI', 'Helvetica Neue', Arial, sans-serif",
    mono: "'Consolas', monospace",
  },
  header: {
    text: "",
  },
  footer: {
    text: "",
  },
  borders: {
    radius: "4px",
    width: "1px",
    color: "#d1d5db",
  },
};

/**
 * Get brand configuration by name.
 */
export function getBrand(name: string): BrandConfig {
  const brands: Record<string, BrandConfig> = {
    fth: FTH_BRAND,
    clean: CLEAN_BRAND,
  };

  return brands[name.toLowerCase()] || CLEAN_BRAND;
}
