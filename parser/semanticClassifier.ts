// ─────────────────────────────────────────────────────────────
// Semantic Classifier — Assign meaning to document sections
// ─────────────────────────────────────────────────────────────

import { Section, DocumentObject } from "../schema/documentSchema";

/** Semantic tag categories */
const SEMANTIC_KEYWORDS: Record<string, string[]> = {
  "legal-agreement": ["agreement", "contract", "binding", "hereby", "parties", "whereas", "terms and conditions"],
  "financial-document": ["invoice", "payment", "total", "amount", "balance", "due", "tax", "revenue", "expense"],
  "educational-material": ["worksheet", "student", "teacher", "class", "lesson", "grade", "assignment", "quiz"],
  "governance-proposal": ["proposal", "resolution", "vote", "quorum", "motion", "committee", "bylaws"],
  "compliance-form": ["compliance", "regulatory", "audit", "disclosure", "kyc", "aml", "verification"],
  "grant-application": ["grant", "applicant", "funding", "budget", "project description", "objectives"],
  "employment-form": ["employee", "employer", "hire", "salary", "position", "department", "date of birth"],
  "corporate-memo": ["memo", "memorandum", "from:", "to:", "subject:", "date:", "re:"],
  "certificate": ["certificate", "certify", "awarded", "recognition", "achievement", "completion"],
  "invoice": ["invoice", "bill to", "ship to", "quantity", "unit price", "subtotal"],
  "report": ["report", "summary", "findings", "conclusion", "recommendation", "analysis"],
  "policy-document": ["policy", "procedure", "guideline", "regulation", "standard", "protocol"],
};

/**
 * Classify the document and assign semantic tags based on content analysis.
 */
export function classifyDocument(doc: DocumentObject, rawText: string): string[] {
  const tags: string[] = [];
  const normalizedText = rawText.toLowerCase();

  // Match semantic keywords
  for (const [category, keywords] of Object.entries(SEMANTIC_KEYWORDS)) {
    const matchCount = keywords.filter((kw) => normalizedText.includes(kw)).length;
    const threshold = Math.max(1, Math.ceil(keywords.length * 0.3));
    if (matchCount >= threshold) {
      tags.push(category);
    }
  }

  // Structural analysis tags
  if (hasSignatureBlocks(doc.structure)) tags.push("requires-signature");
  if (hasTableStructure(doc.structure)) tags.push("contains-tables");
  if (hasNumberedSections(doc.structure)) tags.push("structured-sections");
  if (hasFormFields(doc.structure)) tags.push("form-based");
  if (hasCheckboxes(doc.structure)) tags.push("checklist-based");

  // Page count classification
  if (doc.metadata.pageCount === 1) tags.push("single-page");
  else if (doc.metadata.pageCount <= 5) tags.push("short-document");
  else tags.push("long-document");

  return [...new Set(tags)]; // deduplicate
}

/**
 * Suggest the best transformation modes based on semantic tags.
 */
export function suggestTransformations(tags: string[]): string[] {
  const suggestions: string[] = ["template"]; // always available

  if (tags.includes("legal-agreement") || tags.includes("compliance-form")) {
    suggestions.push("compliance");
  }
  if (tags.includes("governance-proposal") || tags.includes("grant-application")) {
    suggestions.push("governance");
  }
  if (tags.includes("form-based") || tags.includes("educational-material")) {
    suggestions.push("web");
  }
  if (tags.includes("corporate-memo") || tags.includes("certificate")) {
    suggestions.push("brand");
  }

  suggestions.push("archive"); // always available
  return [...new Set(suggestions)];
}

// ── Detection helpers ──────────────────────────────────────

function hasSignatureBlocks(sections: Section[]): boolean {
  return flattenSections(sections).some((s) => s.type === "signature-block");
}

function hasTableStructure(sections: Section[]): boolean {
  return flattenSections(sections).some((s) => s.type === "table");
}

function hasNumberedSections(sections: Section[]): boolean {
  return flattenSections(sections).filter((s) => s.type === "numbered-item").length >= 3;
}

function hasFormFields(sections: Section[]): boolean {
  return flattenSections(sections).filter((s) => s.type === "field").length >= 2;
}

function hasCheckboxes(sections: Section[]): boolean {
  return flattenSections(sections).some((s) => s.type === "checkbox");
}

/** Flatten nested sections into a single array */
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
