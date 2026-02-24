// ─────────────────────────────────────────────────────────────
// Branding Engine — Apply brand identity to document templates
// ─────────────────────────────────────────────────────────────

import { DocumentObject, StyleMap } from "../schema/documentSchema";

/** Brand configuration interface */
export interface BrandConfig {
  name: string;
  colors: {
    primary: string;
    secondary: string;
    accent: string;
    background: string;
    text: string;
  };
  fonts: {
    heading: string;
    body: string;
    mono: string;
  };
  logo?: {
    url: string;
    width: string;
    height: string;
    position: "left" | "center" | "right";
  };
  header?: {
    text: string;
    tagline?: string;
  };
  footer?: {
    text: string;
    address?: string;
    phone?: string;
    email?: string;
    website?: string;
  };
  borders: {
    radius: string;
    width: string;
    color: string;
  };
}

/** Default FTH brand configuration */
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
    heading: "'Montserrat', 'Arial', sans-serif",
    body: "'Open Sans', 'Arial', sans-serif",
    mono: "'Fira Code', 'Consolas', monospace",
  },
  logo: {
    url: "",
    width: "120px",
    height: "auto",
    position: "left",
  },
  header: {
    text: "From The Hart",
    tagline: "Building the Future of Decentralized Governance",
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
 * Apply brand styling to a DocumentObject.
 * Returns modified DocumentObject with brand styles injected.
 */
export function applyBranding(doc: DocumentObject, brand: BrandConfig): DocumentObject {
  const brandedDoc = { ...doc };

  // Override style map with brand
  brandedDoc.styles = mergeBrandStyles(doc.styles, brand);

  // Update metadata title if brand header exists
  if (brand.header?.text) {
    brandedDoc.metadata = {
      ...brandedDoc.metadata,
      title: `${brand.header.text} — ${doc.metadata.title}`,
    };
  }

  return brandedDoc;
}

/**
 * Generate brand-specific CSS.
 */
export function generateBrandCSS(brand: BrandConfig): string {
  return `
/* ── Brand: ${brand.name} ─────────────────────────────── */

:root {
  --brand-primary: ${brand.colors.primary};
  --brand-secondary: ${brand.colors.secondary};
  --brand-accent: ${brand.colors.accent};
  --brand-bg: ${brand.colors.background};
  --brand-text: ${brand.colors.text};
  --brand-heading-font: ${brand.fonts.heading};
  --brand-body-font: ${brand.fonts.body};
  --brand-mono-font: ${brand.fonts.mono};
  --brand-border-radius: ${brand.borders.radius};
  --brand-border-width: ${brand.borders.width};
  --brand-border-color: ${brand.borders.color};
}

body {
  font-family: var(--brand-body-font);
  color: var(--brand-text);
  background-color: var(--brand-bg);
}

h1, h2, h3, h4 {
  font-family: var(--brand-heading-font);
  color: var(--brand-primary);
}

.document-header {
  background: linear-gradient(135deg, var(--brand-primary), var(--brand-secondary));
  color: white;
  padding: 30px 40px;
  border-radius: var(--brand-border-radius) var(--brand-border-radius) 0 0;
  margin-bottom: 30px;
}

.document-header h1 {
  color: white;
  margin: 0;
}

.document-footer {
  border-top: 2px solid var(--brand-primary);
  padding: 20px 40px;
  font-size: 11px;
  color: var(--brand-secondary);
  text-align: center;
  margin-top: 40px;
}

.form-field input,
.form-field select {
  border: var(--brand-border-width) solid var(--brand-border-color);
  border-radius: var(--brand-border-radius);
  padding: 8px 12px;
  font-family: var(--brand-body-font);
}

.form-field input:focus {
  border-color: var(--brand-accent);
  box-shadow: 0 0 0 3px rgba(233, 69, 96, 0.15);
}

.decorative-box {
  border: var(--brand-border-width) solid var(--brand-border-color);
  border-radius: var(--brand-border-radius);
  border-left: 4px solid var(--brand-accent);
}

.signature-line {
  border-bottom: 2px solid var(--brand-primary);
}

table {
  border: var(--brand-border-width) solid var(--brand-border-color);
  border-radius: var(--brand-border-radius);
}

table th {
  background-color: var(--brand-primary);
  color: white;
}

table td {
  border: var(--brand-border-width) solid var(--brand-border-color);
}

.accent-text { color: var(--brand-accent); }
.brand-badge {
  display: inline-block;
  background: var(--brand-accent);
  color: white;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
}
`.trim();
}

/** Merge brand config into existing StyleMap */
function mergeBrandStyles(styles: StyleMap, brand: BrandConfig): StyleMap {
  return {
    ...styles,
    primaryFont: brand.fonts.body,
    secondaryFont: brand.fonts.heading,
    primaryColor: brand.colors.text,
    secondaryColor: brand.colors.secondary,
    accentColor: brand.colors.accent,
    backgroundColor: brand.colors.background,
  };
}
