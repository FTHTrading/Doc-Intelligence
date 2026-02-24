// ─────────────────────────────────────────────────────────────
// HTML Export — Write HTML template to disk
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import { DocumentObject } from "../schema/documentSchema";
import { generateHTMLTemplate } from "../transform/templateGenerator";
import { generateBrandCSS, BrandConfig } from "../transform/brandingEngine";
import { styleMapToCSS } from "../parser/styleExtractor";

/**
 * Export a DocumentObject as a complete HTML template with CSS.
 */
export async function exportHTML(
  doc: DocumentObject,
  outputDir: string,
  options?: {
    filename?: string;
    brand?: BrandConfig;
    includeCSS?: boolean;
  }
): Promise<{ htmlPath: string; cssPath: string }> {
  // Ensure output directory exists
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const baseName = options?.filename || sanitizeFilename(doc.metadata.title);
  const htmlPath = path.join(outputDir, `${baseName}.html`);
  const cssPath = path.join(outputDir, "template.css");

  // Generate HTML
  const html = generateHTMLTemplate(doc);
  fs.writeFileSync(htmlPath, html, "utf-8");
  console.log(`[EXPORT] HTML → ${htmlPath}`);

  // Generate CSS
  if (options?.includeCSS !== false) {
    let css = generateBaseCSS();
    css += "\n\n" + styleMapToCSS(doc.styles);
    if (options?.brand) {
      css += "\n\n" + generateBrandCSS(options.brand);
    }
    fs.writeFileSync(cssPath, css, "utf-8");
    console.log(`[EXPORT] CSS → ${cssPath}`);
  }

  return { htmlPath, cssPath };
}

/** Generate comprehensive base CSS for templates */
function generateBaseCSS(): string {
  return `/* ── Document Intelligence Engine — Base Template CSS ─── */

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Segoe UI', Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  color: #1a1a1a;
  background: #f5f5f5;
}

.document-container {
  max-width: 850px;
  margin: 30px auto;
  background: white;
  box-shadow: 0 2px 20px rgba(0,0,0,0.08);
  border-radius: 8px;
  overflow: hidden;
}

.document-header {
  padding: 30px 40px;
  border-bottom: 2px solid #eee;
}

.document-header h1 {
  font-size: 28px;
  font-weight: 700;
  color: #1a1a1a;
}

.document-body {
  padding: 30px 40px;
}

.document-footer {
  padding: 20px 40px;
  border-top: 1px solid #eee;
  font-size: 11px;
  color: #999;
}

/* ── Section Types ──────────────────────────────── */

.section-header {
  font-size: 24px;
  font-weight: 700;
  margin: 20px 0 10px;
  text-align: center;
}

.section-subheader {
  font-size: 18px;
  font-weight: 600;
  margin: 16px 0 8px;
  color: #333;
}

.section-paragraph {
  margin: 8px 0;
  min-height: 1.6em;
}

/* ── Numbered / Bulleted Items ──────────────────── */

.numbered-item, .bulleted-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin: 6px 0;
  padding: 4px 0;
}

.item-number {
  min-width: 28px;
  font-weight: 600;
  color: #555;
}

.bullet {
  min-width: 16px;
  color: #888;
}

.item-content {
  flex: 1;
  min-height: 1.4em;
}

/* ── Form Fields ────────────────────────────────── */

.form-field {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 8px 0;
}

.field-label {
  font-weight: 600;
  font-size: 13px;
  color: #444;
  min-width: 120px;
}

.field-input {
  flex: 1;
  padding: 6px 10px;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 14px;
  font-family: inherit;
}

.field-input:focus {
  border-color: #2563eb;
  outline: none;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}

/* ── Tables ─────────────────────────────────────── */

.table-placeholder table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
}

.table-placeholder th,
.table-placeholder td {
  border: 1px solid #ddd;
  padding: 8px 12px;
  text-align: left;
  min-width: 80px;
}

.table-placeholder th {
  background: #f7f7f7;
  font-weight: 600;
  font-size: 13px;
}

/* ── Signature Blocks ───────────────────────────── */

.signature-block {
  margin: 40px 0 15px;
}

.signature-line {
  border-bottom: 2px solid #333;
  width: 60%;
  margin-bottom: 5px;
  min-height: 40px;
}

.signature-label {
  font-size: 11px;
  color: #888;
}

.signature-date {
  font-size: 12px;
  color: #888;
  margin-top: 5px;
}

/* ── Checkboxes ─────────────────────────────────── */

.checkbox-item {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 5px 0;
}

.checkbox-item input[type="checkbox"] {
  width: 16px;
  height: 16px;
}

/* ── Decorative Boxes ───────────────────────────── */

.decorative-box {
  border: 2px solid #333;
  border-radius: 6px;
  padding: 15px;
  margin: 12px 0;
}

/* ── Dividers ───────────────────────────────────── */

.section-divider {
  border: none;
  border-top: 1px solid #e0e0e0;
  margin: 15px 0;
}

/* ── Labels ─────────────────────────────────────── */

.standalone-label {
  display: block;
  font-size: 12px;
  font-weight: 600;
  color: #555;
  margin: 10px 0 4px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* ── Section Nesting ────────────────────────────── */

.section-children { padding-left: 20px; }
.depth-1 { padding-left: 15px; }
.depth-2 { padding-left: 30px; }
.depth-3 { padding-left: 45px; }

/* ── Placeholder Styling ────────────────────────── */

[data-placeholder]:empty::before {
  content: attr(data-placeholder);
  color: #bbb;
  font-style: italic;
  pointer-events: none;
}

/* ── Print Styles ───────────────────────────────── */

@media print {
  body { background: white; }
  .document-container { box-shadow: none; margin: 0; border-radius: 0; }
  .no-print { display: none !important; }
}
`;
}

/** Sanitize a string for use as a filename */
function sanitizeFilename(name: string): string {
  return name
    .replace(/[^a-zA-Z0-9\s\-_]/g, "")
    .replace(/\s+/g, "-")
    .toLowerCase()
    .substring(0, 80) || "template";
}
