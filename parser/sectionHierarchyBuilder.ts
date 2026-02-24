// ─────────────────────────────────────────────────────────────
// Section Hierarchy Builder — Build structured document tree
// ─────────────────────────────────────────────────────────────

import { Section, Component, DocumentObject, StyleMap, IngestResult } from "../schema/documentSchema";
import { analyzeLayout } from "./layoutAnalyzer";
import { classifyDocument } from "./semanticClassifier";

/**
 * Build a complete DocumentObject from an IngestResult.
 * This is the main parsing pipeline entry point.
 */
export function buildDocumentObject(ingestResult: IngestResult, sourceFile: string): DocumentObject {
  // Step 1: Analyze layout → get structured sections
  const structure = analyzeLayout(ingestResult.rawBlocks);

  // Step 2: Extract style map from detected patterns
  const styles = extractStyleMap(structure);

  // Step 3: Detect reusable components
  const components = detectComponents(structure);

  // Step 4: Build the document object
  const doc: DocumentObject = {
    metadata: {
      title: ingestResult.metadata.title || "Untitled Document",
      type: ingestResult.format,
      pageCount: ingestResult.pageCount,
      sourceFile,
      ingestedAt: ingestResult.metadata.ingestedAt || new Date().toISOString(),
      language: ingestResult.metadata.language || "en",
      dimensions: ingestResult.metadata.dimensions,
    },
    structure,
    styles,
    components,
    semanticTags: [],
  };

  // Step 5: Classify and assign semantic tags
  doc.semanticTags = classifyDocument(doc, ingestResult.rawText);

  return doc;
}

/**
 * Extract a document-wide style map from section styles.
 */
function extractStyleMap(sections: Section[]): StyleMap {
  const flat = flattenSections(sections);

  // Find most common font sizes
  const fontSizes = flat
    .map((s) => s.style.fontSize)
    .filter(Boolean) as string[];

  const headingSizes = flat
    .filter((s) => s.type === "header" || s.type === "subheader")
    .map((s) => s.style.fontSize)
    .filter(Boolean) as string[];

  const bodySizes = flat
    .filter((s) => s.type === "paragraph" || s.type === "numbered-item")
    .map((s) => s.style.fontSize)
    .filter(Boolean) as string[];

  return {
    primaryFont: "Arial, sans-serif",
    secondaryFont: "Georgia, serif",
    headingSize: headingSizes[0] || "24px",
    bodySize: bodySizes[0] || "14px",
    primaryColor: "#1a1a1a",
    secondaryColor: "#555555",
    accentColor: "#2563eb",
    backgroundColor: "#ffffff",
    lineHeight: "1.6",
  };
}

/**
 * Detect reusable components (tables, form groups, signature blocks).
 */
function detectComponents(sections: Section[]): Component[] {
  const flat = flattenSections(sections);
  const components: Component[] = [];
  let compId = 0;

  // Detect table components
  const tableBlocks = flat.filter((s) => s.type === "table");
  if (tableBlocks.length > 0) {
    components.push({
      id: `comp-${++compId}`,
      name: "Data Table",
      type: "table",
      columns: estimateTableColumns(tableBlocks),
      rows: tableBlocks.length,
      style: tableBlocks[0].style,
    });
  }

  // Detect form field groups
  const fieldBlocks = flat.filter((s) => s.type === "field");
  if (fieldBlocks.length >= 2) {
    components.push({
      id: `comp-${++compId}`,
      name: "Form Fields",
      type: "form-field",
      fields: fieldBlocks.map((f) => f.label),
      style: fieldBlocks[0].style,
    });
  }

  // Detect checkbox groups
  const checkboxBlocks = flat.filter((s) => s.type === "checkbox");
  if (checkboxBlocks.length > 0) {
    components.push({
      id: `comp-${++compId}`,
      name: "Checkbox Group",
      type: "checkbox-group",
      fields: checkboxBlocks.map((c) => c.label),
      style: checkboxBlocks[0].style,
    });
  }

  // Detect signature blocks
  const signatureBlocks = flat.filter((s) => s.type === "signature-block");
  if (signatureBlocks.length > 0) {
    components.push({
      id: `comp-${++compId}`,
      name: "Signature Block",
      type: "signature",
      style: signatureBlocks[0].style,
    });
  }

  // Detect list components
  const numberedItems = flat.filter((s) => s.type === "numbered-item");
  if (numberedItems.length >= 3) {
    components.push({
      id: `comp-${++compId}`,
      name: "Numbered List",
      type: "list",
      rows: numberedItems.length,
      style: numberedItems[0].style,
    });
  }

  const bulletedItems = flat.filter((s) => s.type === "bulleted-item");
  if (bulletedItems.length >= 3) {
    components.push({
      id: `comp-${++compId}`,
      name: "Bulleted List",
      type: "list",
      rows: bulletedItems.length,
      style: bulletedItems[0].style,
    });
  }

  return components;
}

/** Estimate number of table columns from pipe-separated text */
function estimateTableColumns(tableBlocks: Section[]): number {
  if (tableBlocks.length === 0) return 0;
  // Label might contain pipe separators from the original text
  const maxPipes = Math.max(
    ...tableBlocks.map((b) => (b.label.match(/\|/g) || []).length)
  );
  return Math.max(2, maxPipes + 1);
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
