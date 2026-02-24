// ─────────────────────────────────────────────────────────────
// Template Generator — Build empty reusable templates
// ─────────────────────────────────────────────────────────────

import { DocumentObject, Section, SectionStyle } from "../schema/documentSchema";
import { sectionStyleToInline } from "../parser/styleExtractor";

/**
 * Generate a clean HTML template from a DocumentObject.
 * All content fields are empty — pure structure replication.
 */
export function generateHTMLTemplate(doc: DocumentObject): string {
  const sections = renderSections(doc.structure);

  return `<!DOCTYPE html>
<html lang="${doc.metadata.language}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="Document Intelligence Engine">
  <meta name="source" content="${escapeHtml(doc.metadata.sourceFile)}">
  <meta name="created" content="${doc.metadata.ingestedAt}">
  <title>${escapeHtml(doc.metadata.title)} — Template</title>
  <link rel="stylesheet" href="template.css">
  <style>
    /* Inline overrides from source document */
    [contenteditable]:hover {
      outline: 2px dashed #2563eb;
      outline-offset: 2px;
    }
    [contenteditable]:focus {
      outline: 2px solid #2563eb;
      outline-offset: 2px;
      background-color: #f0f7ff;
    }
    @media print {
      [contenteditable] { outline: none !important; background: none !important; }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>
  <div class="document-container">
    <header class="document-header">
      <h1 contenteditable="true" data-placeholder="Document Title"></h1>
    </header>

    <main class="document-body">
${sections}
    </main>

    <footer class="document-footer">
      <div class="footer-content" contenteditable="true" data-placeholder="Footer"></div>
    </footer>
  </div>
</body>
</html>`;
}

/** Render sections recursively into HTML */
function renderSections(sections: Section[], indentLevel = 3): string {
  const indent = "  ".repeat(indentLevel);
  let html = "";

  for (const section of sections) {
    html += renderSection(section, indent);

    if (section.children.length > 0) {
      html += `${indent}<div class="section-children depth-${section.depth + 1}">\n`;
      html += renderSections(section.children, indentLevel + 1);
      html += `${indent}</div>\n`;
    }
  }

  return html;
}

/** Render a single section to HTML */
function renderSection(section: Section, indent: string): string {
  const style = sectionStyleToInline(section.style);
  const styleAttr = style ? ` style="${style}"` : "";
  const label = section.label ? escapeHtml(section.label) : "";

  switch (section.type) {
    case "header":
      return `${indent}<h1 class="section-header" contenteditable="true" data-placeholder="${label}"${styleAttr}></h1>\n`;

    case "subheader":
      return `${indent}<h2 class="section-subheader" contenteditable="true" data-placeholder="${label}"${styleAttr}></h2>\n`;

    case "paragraph":
      return `${indent}<p class="section-paragraph" contenteditable="true" data-placeholder="Enter text..."${styleAttr}></p>\n`;

    case "numbered-item":
      return `${indent}<div class="numbered-item"${styleAttr}>\n` +
        `${indent}  <span class="item-number">${label}</span>\n` +
        `${indent}  <span class="item-content" contenteditable="true" data-placeholder=""></span>\n` +
        `${indent}</div>\n`;

    case "bulleted-item":
      return `${indent}<div class="bulleted-item"${styleAttr}>\n` +
        `${indent}  <span class="bullet">•</span>\n` +
        `${indent}  <span class="item-content" contenteditable="true" data-placeholder=""></span>\n` +
        `${indent}</div>\n`;

    case "field":
      return `${indent}<div class="form-field"${styleAttr}>\n` +
        `${indent}  <label class="field-label">${label}</label>\n` +
        `${indent}  <input type="text" class="field-input" placeholder="" />\n` +
        `${indent}</div>\n`;

    case "table":
      return `${indent}<div class="table-placeholder"${styleAttr}>\n` +
        `${indent}  <table>\n` +
        `${indent}    <thead><tr><th contenteditable="true"></th><th contenteditable="true"></th><th contenteditable="true"></th></tr></thead>\n` +
        `${indent}    <tbody><tr><td contenteditable="true"></td><td contenteditable="true"></td><td contenteditable="true"></td></tr></tbody>\n` +
        `${indent}  </table>\n` +
        `${indent}</div>\n`;

    case "signature-block":
      return `${indent}<div class="signature-block"${styleAttr}>\n` +
        `${indent}  <div class="signature-line"></div>\n` +
        `${indent}  <label class="signature-label">${label || "Signature"}</label>\n` +
        `${indent}  <div class="signature-date">Date: ____________</div>\n` +
        `${indent}</div>\n`;

    case "checkbox":
      return `${indent}<div class="checkbox-item"${styleAttr}>\n` +
        `${indent}  <input type="checkbox" />\n` +
        `${indent}  <span contenteditable="true" data-placeholder="${label}"></span>\n` +
        `${indent}</div>\n`;

    case "divider":
      return `${indent}<hr class="section-divider" />\n`;

    case "decorative-box":
      return `${indent}<div class="decorative-box"${styleAttr}>\n` +
        `${indent}  <div contenteditable="true" data-placeholder=""></div>\n` +
        `${indent}</div>\n`;

    case "label":
      return `${indent}<label class="standalone-label"${styleAttr}>${label}</label>\n`;

    case "footer":
      return `${indent}<div class="section-footer"${styleAttr} contenteditable="true" data-placeholder="Footer text"></div>\n`;

    default:
      return `${indent}<div class="unknown-block" contenteditable="true" data-placeholder=""${styleAttr}></div>\n`;
  }
}

/** Escape HTML entities */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
