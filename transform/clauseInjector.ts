// ─────────────────────────────────────────────────────────────
// Clause Injector — Insert compliance / legal clauses
// ─────────────────────────────────────────────────────────────

import { DocumentObject, Section, TransformationRule } from "../schema/documentSchema";
import { ComplianceClause, ComplianceWrapper, STANDARD_CLAUSES, SignatureBlock, AuditEntry } from "../schema/complianceSchema";

/**
 * Apply transformation rules to a DocumentObject.
 * Rules can match labels/types and replace, inject, or restyle sections.
 */
export function applyTransformationRules(
  doc: DocumentObject,
  rules: TransformationRule[]
): DocumentObject {
  const transformed = { ...doc };
  transformed.structure = applyRulesToSections(doc.structure, rules);
  return transformed;
}

/**
 * Inject compliance clauses into a DocumentObject.
 * Clauses are added as new sections at the end of the document.
 */
export function injectComplianceClauses(
  doc: DocumentObject,
  clauses?: ComplianceClause[],
  placeholderValues?: Record<string, string>
): DocumentObject {
  const clausesToInject = clauses || STANDARD_CLAUSES.filter((c) => c.required);
  const injected = { ...doc };

  // Add divider before compliance section
  const divider: Section = {
    id: `compliance-divider`,
    type: "divider",
    depth: 0,
    label: "",
    content: "",
    children: [],
    style: { margin: "30px 0" },
  };

  // Add compliance header
  const header: Section = {
    id: `compliance-header`,
    type: "header",
    depth: 0,
    label: "COMPLIANCE & LEGAL NOTICES",
    content: "",
    children: [],
    style: { fontSize: "18px", fontWeight: "bold", textAlign: "center" },
  };

  // Convert clauses to sections
  const clauseSections: Section[] = clausesToInject.map((clause, i) => ({
    id: `clause-${i + 1}`,
    type: "paragraph" as const,
    depth: 0,
    label: clause.title,
    content: "", // Empty in template mode — clause body available via data attribute
    children: [],
    style: { fontSize: "11px", color: "#555", padding: "8px", borderStyle: "1px solid #eee" },
  }));

  injected.structure = [
    ...doc.structure,
    divider,
    header,
    ...clauseSections,
  ];

  // Add compliance tag
  if (!injected.semanticTags.includes("compliance-injected")) {
    injected.semanticTags.push("compliance-injected");
  }

  return injected;
}

/**
 * Build a full compliance wrapper for a document.
 */
export function buildComplianceWrapper(
  doc: DocumentObject,
  options?: {
    classification?: "public" | "internal" | "confidential" | "restricted";
    signatures?: SignatureBlock[];
    retentionDays?: number;
    approvedBy?: string[];
  }
): ComplianceWrapper {
  return {
    classification: options?.classification || "internal",
    clauses: STANDARD_CLAUSES.filter((c) => c.required),
    signatures: options?.signatures || [
      {
        role: "Authorized Signatory",
        name: "",
        title: "",
        date: "",
        signatureField: true,
        witnessRequired: false,
      },
    ],
    auditLog: [
      {
        action: "document-created",
        performedBy: "system",
        timestamp: new Date().toISOString(),
        details: `Document "${doc.metadata.title}" created from ${doc.metadata.sourceFile}`,
        fingerprint: {
          sha256: "",
          merkleRoot: "",
          version: "1.0.0",
          timestamp: Date.now(),
          sourceHash: "",
        },
      },
    ],
    retentionPeriodDays: options?.retentionDays || 2555, // ~7 years
    reviewDate: getNextReviewDate(),
    approvedBy: options?.approvedBy || [],
  };
}

/**
 * Add signature blocks to a DocumentObject.
 */
export function injectSignatureBlocks(
  doc: DocumentObject,
  count: number = 2
): DocumentObject {
  const injected = { ...doc };
  const signatureBlocks: Section[] = [];

  for (let i = 0; i < count; i++) {
    signatureBlocks.push({
      id: `sig-block-${i + 1}`,
      type: "signature-block",
      depth: 0,
      label: `Signature ${i + 1}`,
      content: "",
      children: [],
      style: { margin: "40px 0 10px 0", borderStyle: "none none 2px solid none" },
    });

    // Add name/title/date labels under each signature
    signatureBlocks.push({
      id: `sig-info-${i + 1}`,
      type: "field",
      depth: 0,
      label: "Printed Name / Title / Date",
      content: "",
      children: [],
      style: { fontSize: "11px", color: "#888" },
    });
  }

  injected.structure = [...doc.structure, ...signatureBlocks];
  return injected;
}

// ── Helpers ──────────────────────────────────────────────────

function applyRulesToSections(sections: Section[], rules: TransformationRule[]): Section[] {
  return sections.map((section) => {
    let modified = { ...section };

    for (const rule of rules) {
      const regex = new RegExp(rule.match, "i");

      // Match against label or type
      if (regex.test(section.label) || regex.test(section.type)) {
        // Apply style override
        if (rule.styleOverride) {
          modified.style = { ...modified.style, ...rule.styleOverride };
        }

        // Replace label text
        if (rule.replaceWith) {
          modified.label = section.label.replace(regex, rule.replaceWith);
        }
      }
    }

    // Recurse into children
    if (modified.children.length > 0) {
      modified.children = applyRulesToSections(modified.children, rules);
    }

    return modified;
  });
}

function getNextReviewDate(): string {
  const date = new Date();
  date.setFullYear(date.getFullYear() + 1);
  return date.toISOString().split("T")[0];
}

/** Fill template placeholders in clause text */
export function resolveClausePlaceholders(
  clause: ComplianceClause,
  values: Record<string, string>
): string {
  let text = clause.body;
  for (const [key, value] of Object.entries(values)) {
    text = text.replace(new RegExp(`\\{\\{${key}\\}\\}`, "g"), value);
  }
  return text;
}
