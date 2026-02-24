// ─────────────────────────────────────────────────────────────
// Compliance Schema — Legal / Regulatory Document Layer
// ─────────────────────────────────────────────────────────────

import { DocumentFingerprint } from "./documentSchema";

/** Compliance classification levels */
export type ComplianceLevel = "public" | "internal" | "confidential" | "restricted";

/** Standard compliance clause types */
export type ClauseType =
  | "risk-disclosure"
  | "liability-limitation"
  | "data-privacy"
  | "anti-money-laundering"
  | "kyc-requirement"
  | "audit-trail"
  | "signature-requirement"
  | "version-control"
  | "governing-law"
  | "dispute-resolution"
  | "confidentiality"
  | "intellectual-property"
  | "force-majeure"
  | "termination"
  | "indemnification"
  | "custom";

/** A compliance clause to inject into documents */
export interface ComplianceClause {
  id: string;
  type: ClauseType;
  title: string;
  body: string;           // template text with {{placeholders}}
  required: boolean;
  jurisdiction?: string;
  effectiveDate?: string;
}

/** Signature block for legal documents */
export interface SignatureBlock {
  role: string;
  name: string;
  title: string;
  date: string;
  signatureField: boolean;
  witnessRequired: boolean;
}

/** Audit log entry */
export interface AuditEntry {
  action: string;
  performedBy: string;
  timestamp: string;
  details: string;
  fingerprint: DocumentFingerprint;
}

/** Full compliance wrapper for a document */
export interface ComplianceWrapper {
  classification: ComplianceLevel;
  clauses: ComplianceClause[];
  signatures: SignatureBlock[];
  auditLog: AuditEntry[];
  retentionPeriodDays: number;
  reviewDate: string;
  approvedBy: string[];
}

/** Standard compliance clause library */
export const STANDARD_CLAUSES: ComplianceClause[] = [
  {
    id: "risk-001",
    type: "risk-disclosure",
    title: "Risk Disclosure Statement",
    body: "This document is provided for informational purposes only. {{entity_name}} makes no representations or warranties regarding the accuracy, completeness, or suitability of the information contained herein.",
    required: true,
  },
  {
    id: "privacy-001",
    type: "data-privacy",
    title: "Data Privacy Notice",
    body: "Personal data collected through this document will be processed in accordance with applicable data protection regulations. For inquiries, contact {{privacy_contact}}.",
    required: true,
  },
  {
    id: "aml-001",
    type: "anti-money-laundering",
    title: "AML/KYC Compliance",
    body: "All parties are subject to anti-money laundering and know-your-customer verification requirements as mandated by {{jurisdiction}} law.",
    required: false,
  },
  {
    id: "audit-001",
    type: "audit-trail",
    title: "Audit Trail Notice",
    body: "All modifications to this document are logged and traceable. Document integrity is verified via cryptographic hash: {{document_hash}}.",
    required: true,
  },
  {
    id: "ip-001",
    type: "intellectual-property",
    title: "Intellectual Property Notice",
    body: "All content, structure, and design elements within this document are the intellectual property of {{entity_name}} unless otherwise noted.",
    required: false,
  },
  {
    id: "version-001",
    type: "version-control",
    title: "Version Control",
    body: "Document Version: {{version}} | Last Modified: {{last_modified}} | Hash: {{document_hash}}",
    required: true,
  },
];
