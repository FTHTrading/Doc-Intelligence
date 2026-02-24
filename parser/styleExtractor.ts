// ─────────────────────────────────────────────────────────────
// Style Extractor — Extract visual style fingerprint
// ─────────────────────────────────────────────────────────────

import { Section, StyleMap, SectionStyle } from "../schema/documentSchema";

/**
 * Extract a comprehensive style map from document sections.
 * Used for branding injection and style replication.
 */
export function extractStyles(sections: Section[]): StyleMap {
  const flat = flattenSections(sections);

  return {
    primaryFont: detectPrimaryFont(flat),
    secondaryFont: detectSecondaryFont(flat),
    headingSize: detectHeadingSize(flat),
    bodySize: detectBodySize(flat),
    primaryColor: detectPrimaryColor(flat),
    secondaryColor: detectSecondaryColor(flat),
    accentColor: detectAccentColor(flat),
    backgroundColor: "#ffffff",
    lineHeight: "1.6",
  };
}

/**
 * Generate a CSS string from a StyleMap.
 */
export function styleMapToCSS(styles: StyleMap): string {
  return `
:root {
  --primary-font: ${styles.primaryFont};
  --secondary-font: ${styles.secondaryFont};
  --heading-size: ${styles.headingSize};
  --body-size: ${styles.bodySize};
  --primary-color: ${styles.primaryColor};
  --secondary-color: ${styles.secondaryColor};
  --accent-color: ${styles.accentColor};
  --bg-color: ${styles.backgroundColor};
  --line-height: ${styles.lineHeight};
}

body {
  font-family: var(--primary-font);
  font-size: var(--body-size);
  color: var(--primary-color);
  background-color: var(--bg-color);
  line-height: var(--line-height);
}

h1, h2, h3 {
  font-family: var(--secondary-font);
  color: var(--primary-color);
}

h1 { font-size: var(--heading-size); }
h2 { font-size: calc(var(--heading-size) * 0.85); }
h3 { font-size: calc(var(--heading-size) * 0.7); }

a, .accent { color: var(--accent-color); }
.secondary { color: var(--secondary-color); }
`.trim();
}

/**
 * Generate inline style string from SectionStyle.
 */
export function sectionStyleToInline(style: SectionStyle): string {
  const props: string[] = [];

  if (style.fontFamily) props.push(`font-family: ${style.fontFamily}`);
  if (style.fontSize) props.push(`font-size: ${style.fontSize}`);
  if (style.fontWeight) props.push(`font-weight: ${style.fontWeight}`);
  if (style.textAlign) props.push(`text-align: ${style.textAlign}`);
  if (style.color) props.push(`color: ${style.color}`);
  if (style.backgroundColor) props.push(`background-color: ${style.backgroundColor}`);
  if (style.padding) props.push(`padding: ${style.padding}`);
  if (style.margin) props.push(`margin: ${style.margin}`);
  if (style.width) props.push(`width: ${style.width}`);
  if (style.height) props.push(`height: ${style.height}`);

  return props.join("; ");
}

// ── Detection helpers ──────────────────────────────────────

function detectPrimaryFont(sections: Section[]): string {
  const fonts = sections
    .map((s) => s.style.fontFamily)
    .filter(Boolean);
  return mostCommon(fonts as string[]) || "Arial, sans-serif";
}

function detectSecondaryFont(sections: Section[]): string {
  const headerFonts = sections
    .filter((s) => s.type === "header" || s.type === "subheader")
    .map((s) => s.style.fontFamily)
    .filter(Boolean);
  return mostCommon(headerFonts as string[]) || "Georgia, serif";
}

function detectHeadingSize(sections: Section[]): string {
  const sizes = sections
    .filter((s) => s.type === "header")
    .map((s) => s.style.fontSize)
    .filter(Boolean);
  return sizes[0] || "24px";
}

function detectBodySize(sections: Section[]): string {
  const sizes = sections
    .filter((s) => s.type === "paragraph")
    .map((s) => s.style.fontSize)
    .filter(Boolean);
  return mostCommon(sizes as string[]) || "14px";
}

function detectPrimaryColor(sections: Section[]): string {
  const colors = sections
    .map((s) => s.style.color)
    .filter(Boolean);
  return mostCommon(colors as string[]) || "#1a1a1a";
}

function detectSecondaryColor(sections: Section[]): string {
  const colors = sections
    .filter((s) => s.type === "label" || s.type === "footer")
    .map((s) => s.style.color)
    .filter(Boolean);
  return mostCommon(colors as string[]) || "#555555";
}

function detectAccentColor(sections: Section[]): string {
  return "#2563eb"; // default accent, would be extracted from links/highlights
}

/** Find most common string in array */
function mostCommon(arr: string[]): string | null {
  if (arr.length === 0) return null;
  const counts = new Map<string, number>();
  arr.forEach((v) => counts.set(v, (counts.get(v) || 0) + 1));
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

/** Flatten nested sections */
function flattenSections(sections: Section[]): Section[] {
  const flat: Section[] = [];
  const walk = (list: Section[]) => {
    for (const s of list) {
      flat.push(s);
      if (s.children.length > 0) walk(s.children);
    }
  };
  walk(sections);
  return flat;
}
