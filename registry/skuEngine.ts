// ─────────────────────────────────────────────────────────────
// SKU Identity Engine — Sovereign Document Identity Codes
//
// Generates deterministic, human-readable document identity:
//   {DOCTYPE}-{SUBTYPE}-{JURISDICTION}-{YEAR}-V{VER}-{HASH}
//
// Examples:
//   BOND-INDENTURE-US-2026-V1-8F3A
//   DAO-PROPOSAL-GLOBAL-2025-V1-C4E7
//   CONTRACT-NDA-US-2025-V2-9B1D
//   COMPLIANCE-KYC-EU-2025-V1-A2F0
//   CREDENTIAL-DIPLOMA-US-2024-V1-7E2B
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import { DocumentObject, ExportMode } from "../schema/documentSchema";

/** Document type classification for SKU generation */
export type DocTypeSKU =
  | "BOND"
  | "CONTRACT"
  | "DAO"
  | "COMPLIANCE"
  | "CREDENTIAL"
  | "INVOICE"
  | "LEGAL"
  | "REPORT"
  | "TEMPLATE"
  | "MEMO"
  | "POLICY"
  | "AGREEMENT"
  | "PROPOSAL"
  | "CERTIFICATE"
  | "RECORD"
  | "DOC";

/** Document subtype classification */
export type DocSubtype =
  | "INDENTURE"
  | "NDA"
  | "PROPOSAL"
  | "KYC"
  | "AML"
  | "DIPLOMA"
  | "TRANSCRIPT"
  | "GENERAL"
  | "TERM-SHEET"
  | "OFFERING"
  | "PROSPECTUS"
  | "RESOLUTION"
  | "BYLAW"
  | "AMENDMENT"
  | "ADDENDUM"
  | "RECEIPT"
  | "STANDARD";

/** Jurisdiction codes */
export type Jurisdiction =
  | "US"
  | "EU"
  | "UK"
  | "CH"   // Switzerland
  | "SG"   // Singapore
  | "HK"   // Hong Kong
  | "JP"   // Japan
  | "AU"   // Australia
  | "CA"   // Canada
  | "GLOBAL"
  | "OTHER";

/** Full SKU identity structure */
export interface DocumentSKU {
  /** Full SKU string: DOCTYPE-SUBTYPE-JURISDICTION-YEAR-VERSION-HASH */
  sku: string;
  /** Document type component */
  docType: DocTypeSKU;
  /** Document subtype */
  subtype: DocSubtype;
  /** Jurisdiction code */
  jurisdiction: Jurisdiction;
  /** Year component */
  year: number;
  /** Version number */
  version: number;
  /** Short hash suffix (4 hex chars) */
  hashSuffix: string;
  /** Full SHA-256 of the document */
  fullHash: string;
  /** Generation timestamp */
  generatedAt: string;
}

/** SKU generation options */
export interface SKUOptions {
  docType?: DocTypeSKU;
  subtype?: DocSubtype;
  jurisdiction?: Jurisdiction;
  version?: number;
  year?: number;
}

/**
 * Generate a sovereign document SKU identity.
 */
export function generateSKU(
  doc: DocumentObject,
  options?: SKUOptions
): DocumentSKU {
  // Detect document type from semantic tags and content
  const docType = options?.docType || detectDocType(doc);
  const subtype = options?.subtype || detectSubtype(doc, docType);
  const jurisdiction = options?.jurisdiction || detectJurisdiction(doc);
  const version = options?.version || 1;
  const year = options?.year || new Date().getFullYear();

  // Generate hash suffix from document content
  const docString = JSON.stringify(doc);
  const fullHash = crypto.createHash("sha256").update(docString).digest("hex");
  const hashSuffix = fullHash.substring(0, 4).toUpperCase();

  // Build the SKU
  const sku = `${docType}-${subtype}-${jurisdiction}-${year}-V${version}-${hashSuffix}`;

  return {
    sku,
    docType,
    subtype,
    jurisdiction,
    year,
    version,
    hashSuffix,
    fullHash,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Generate a SKU from export mode (secondary path).
 */
export function generateSKUFromMode(
  mode: ExportMode,
  doc: DocumentObject,
  options?: SKUOptions
): DocumentSKU {
  const modeTypeMap: Record<ExportMode, DocTypeSKU> = {
    template: "TEMPLATE",
    governance: "DAO",
    compliance: "COMPLIANCE",
    brand: "DOC",
    web: "DOC",
    archive: "RECORD",
  };

  return generateSKU(doc, {
    ...options,
    docType: options?.docType || modeTypeMap[mode],
  });
}

// ── Detection Heuristics ─────────────────────────────────────

/** Detect document type from semantic tags and content */
function detectDocType(doc: DocumentObject): DocTypeSKU {
  const tags = doc.semanticTags.map((t) => t.toLowerCase());
  const title = doc.metadata.title.toLowerCase();

  // Check semantic tags first
  if (tags.includes("governance") || tags.includes("dao")) return "DAO";
  if (tags.includes("bond") || tags.includes("indenture")) return "BOND";
  if (tags.includes("contract") || tags.includes("agreement")) return "CONTRACT";
  if (tags.includes("compliance") || tags.includes("regulatory")) return "COMPLIANCE";
  if (tags.includes("invoice") || tags.includes("receipt")) return "INVOICE";
  if (tags.includes("credential") || tags.includes("certificate")) return "CREDENTIAL";
  if (tags.includes("proposal")) return "PROPOSAL";
  if (tags.includes("policy")) return "POLICY";
  if (tags.includes("legal")) return "LEGAL";
  if (tags.includes("report")) return "REPORT";

  // Fallback to title keywords
  if (title.includes("bond") || title.includes("indenture")) return "BOND";
  if (title.includes("contract") || title.includes("nda") || title.includes("agreement")) return "CONTRACT";
  if (title.includes("proposal") || title.includes("dao") || title.includes("governance")) return "DAO";
  if (title.includes("compliance") || title.includes("kyc") || title.includes("aml")) return "COMPLIANCE";
  if (title.includes("invoice") || title.includes("receipt")) return "INVOICE";
  if (title.includes("certificate") || title.includes("diploma") || title.includes("credential")) return "CREDENTIAL";
  if (title.includes("policy")) return "POLICY";
  if (title.includes("memo")) return "MEMO";
  if (title.includes("report")) return "REPORT";

  return "DOC";
}

/** Detect subtype from document content */
function detectSubtype(doc: DocumentObject, docType: DocTypeSKU): DocSubtype {
  const title = doc.metadata.title.toLowerCase();
  const tags = doc.semanticTags.map((t) => t.toLowerCase());

  switch (docType) {
    case "BOND":
      if (title.includes("indenture")) return "INDENTURE";
      if (title.includes("term") && title.includes("sheet")) return "TERM-SHEET";
      if (title.includes("offering")) return "OFFERING";
      if (title.includes("prospectus")) return "PROSPECTUS";
      return "STANDARD";

    case "CONTRACT":
      if (title.includes("nda") || title.includes("non-disclosure")) return "NDA";
      if (title.includes("addendum")) return "ADDENDUM";
      if (title.includes("amendment")) return "AMENDMENT";
      return "GENERAL";

    case "DAO":
      if (tags.includes("proposal") || title.includes("proposal")) return "PROPOSAL";
      if (title.includes("resolution")) return "RESOLUTION";
      if (title.includes("bylaw")) return "BYLAW";
      return "PROPOSAL";

    case "COMPLIANCE":
      if (title.includes("kyc") || tags.includes("kyc")) return "KYC";
      if (title.includes("aml") || tags.includes("aml")) return "AML";
      return "GENERAL";

    case "CREDENTIAL":
      if (title.includes("diploma")) return "DIPLOMA";
      if (title.includes("transcript")) return "TRANSCRIPT";
      return "GENERAL";

    case "INVOICE":
      return "RECEIPT";

    default:
      return "STANDARD";
  }
}

/** Detect jurisdiction from document content */
function detectJurisdiction(doc: DocumentObject): Jurisdiction {
  const allText = [
    doc.metadata.title,
    ...doc.semanticTags,
    ...flattenContent(doc.structure),
  ]
    .join(" ")
    .toLowerCase();

  // Check for jurisdiction indicators
  if (allText.includes("united states") || allText.includes("u.s.") || allText.includes("delaware") || allText.includes("new york") || allText.includes("sec ")) return "US";
  if (allText.includes("european union") || allText.includes("gdpr") || allText.includes("eu ")) return "EU";
  if (allText.includes("united kingdom") || allText.includes("uk ") || allText.includes("england")) return "UK";
  if (allText.includes("switzerland") || allText.includes("swiss") || allText.includes("finma")) return "CH";
  if (allText.includes("singapore") || allText.includes("mas ")) return "SG";
  if (allText.includes("hong kong") || allText.includes("sfc ")) return "HK";
  if (allText.includes("japan") || allText.includes("jfsa")) return "JP";
  if (allText.includes("australia") || allText.includes("asic")) return "AU";
  if (allText.includes("canada") || allText.includes("csa ")) return "CA";

  return "GLOBAL";
}

/** Flatten section content for text analysis */
function flattenContent(sections: any[]): string[] {
  const texts: string[] = [];
  const walk = (list: any[]) => {
    for (const s of list) {
      if (s.label) texts.push(s.label);
      if (s.content) texts.push(s.content);
      if (s.children?.length > 0) walk(s.children);
    }
  };
  walk(sections);
  return texts;
}

/**
 * Parse a SKU string back into its components.
 */
export function parseSKU(sku: string): Partial<DocumentSKU> | null {
  const parts = sku.split("-");
  if (parts.length < 6) return null;

  // Handle multi-word subtypes (e.g., TERM-SHEET)
  // Format: TYPE-SUBTYPE-JURISDICTION-YEAR-VERSION-HASH
  // Work backwards from the end
  const hashSuffix = parts[parts.length - 1];
  const versionStr = parts[parts.length - 2];
  const yearStr = parts[parts.length - 3];
  const jurisdiction = parts[parts.length - 4] as Jurisdiction;
  const docType = parts[0] as DocTypeSKU;
  const subtype = parts.slice(1, parts.length - 4).join("-") as DocSubtype;

  const version = parseInt(versionStr.replace("V", ""), 10);
  const year = parseInt(yearStr, 10);

  if (isNaN(version) || isNaN(year)) return null;

  return {
    sku,
    docType,
    subtype,
    jurisdiction,
    year,
    version,
    hashSuffix,
  };
}
