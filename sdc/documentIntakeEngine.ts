// ─────────────────────────────────────────────────────────────
// Secure Document Control — Document Intake Engine
//
// Every document entering the SDC must pass through intake.
// Classification, risk tiering, mode binding, access policy.
//
// Classification: Legal | Financial | Compliance | IP |
//                 Operational | Governance | Research
//
// Risk Tier: LOW | HIGH | CRITICAL
//
// Mode Binding: INFRA | ISSUER | VENUE | CROSS-MODE
//
// Nothing bypasses intake. No document exists in the system
// without a classification, risk tier, and access policy.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

export type DocumentClassification =
  | "legal"
  | "financial"
  | "compliance"
  | "ip"
  | "operational"
  | "governance"
  | "research"
  | "custody"
  | "issuance"
  | "venue"
  | "treasury"
  | "risk"
  | "counterparty"
  | "public";

export type RiskTier = "LOW" | "HIGH" | "CRITICAL";

export type SystemMode = "INFRA" | "ISSUER" | "VENUE" | "CROSS-MODE";

export type ExportPolicy =
  | "NONE"          // No export allowed
  | "VIEW_ONLY"     // Secure viewer only
  | "PDF_ONLY"      // PDF export, no Word
  | "PDF_PASSWORD"  // PDF with recipient-specific password
  | "DOCX_RESTRICTED" // Word read-only with watermark
  | "FULL";         // All exports allowed (internal only)

export type WatermarkPolicy =
  | "NONE"          // No watermark (internal draft only)
  | "STANDARD"      // Visible diagonal + footer hash
  | "FORENSIC"      // Standard + invisible micro-fingerprints
  | "MAXIMUM";      // Forensic + spacing variations + Unicode markers

export type DocumentState =
  | "DRAFT"
  | "INTERNAL"
  | "EXTERNAL_VIEW"
  | "SIGNED"
  | "LOCKED"
  | "ARCHIVED"
  | "REVOKED";

export interface AccessPolicy {
  /** Roles allowed to access */
  allowedRoles: string[];
  /** Specific entity IDs allowed */
  allowedEntities: string[];
  /** Maximum number of views per recipient */
  maxViewsPerRecipient: number;
  /** Access link expiration in hours */
  linkExpiryHours: number;
  /** Require OTP for access */
  requireOTP: boolean;
  /** Require device binding */
  requireDeviceBinding: boolean;
  /** Geographic restrictions (ISO country codes, empty = no restriction) */
  geoRestrictions: string[];
  /** IP allowlist (empty = no restriction) */
  ipAllowlist: string[];
  /** Re-authentication timeout in minutes */
  reauthTimeoutMinutes: number;
}

export interface IntakeRecord {
  /** Unique intake record ID */
  intakeId: string;
  /** Document ID from the pipeline */
  documentId: string;
  /** Document title */
  documentTitle: string;
  /** Document hash (SHA-256) */
  documentHash: string;
  /** SKU if assigned */
  sku?: string;
  /** Classification */
  classification: DocumentClassification;
  /** Risk tier */
  riskTier: RiskTier;
  /** System mode binding */
  modeBinding: SystemMode;
  /** Document owner */
  owner: {
    name: string;
    email: string;
    entity?: string;
  };
  /** Access policy */
  accessPolicy: AccessPolicy;
  /** Watermark policy */
  watermarkPolicy: WatermarkPolicy;
  /** Export policy */
  exportPolicy: ExportPolicy;
  /** Current document state */
  state: DocumentState;
  /** State history */
  stateHistory: Array<{
    from: DocumentState;
    to: DocumentState;
    timestamp: string;
    actor: string;
    reason?: string;
  }>;
  /** Confidentiality notice text */
  confidentialityNotice: string;
  /** Tracking enabled */
  trackingEnabled: boolean;
  /** Creation timestamp */
  createdAt: string;
  /** Last modified timestamp */
  updatedAt: string;
  /** Intake record hash */
  intakeHash: string;
}

// ── Classification Rules ─────────────────────────────────────

interface ClassificationRule {
  keywords: string[];
  classification: DocumentClassification;
  riskTier: RiskTier;
  modeBinding: SystemMode;
  watermarkPolicy: WatermarkPolicy;
  exportPolicy: ExportPolicy;
}

const CLASSIFICATION_RULES: ClassificationRule[] = [
  {
    keywords: ["msa", "master services", "agreement", "contract", "terms", "nda", "confidential", "non-disclosure"],
    classification: "legal",
    riskTier: "HIGH",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "FORENSIC",
    exportPolicy: "PDF_PASSWORD",
  },
  {
    keywords: ["bond", "coupon", "offering", "ppm", "subscription", "term sheet", "prospectus"],
    classification: "issuance",
    riskTier: "CRITICAL",
    modeBinding: "ISSUER",
    watermarkPolicy: "MAXIMUM",
    exportPolicy: "VIEW_ONLY",
  },
  {
    keywords: ["custody", "vault", "escrow", "collateral", "mpc", "signing", "key management"],
    classification: "custody",
    riskTier: "CRITICAL",
    modeBinding: "INFRA",
    watermarkPolicy: "MAXIMUM",
    exportPolicy: "NONE",
  },
  {
    keywords: ["aml", "kyc", "sanctions", "bsa", "msb", "compliance", "travel rule"],
    classification: "compliance",
    riskTier: "CRITICAL",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "FORENSIC",
    exportPolicy: "PDF_ONLY",
  },
  {
    keywords: ["treasury", "reserve", "allocation", "funding", "wire", "settlement"],
    classification: "treasury",
    riskTier: "HIGH",
    modeBinding: "INFRA",
    watermarkPolicy: "FORENSIC",
    exportPolicy: "PDF_PASSWORD",
  },
  {
    keywords: ["order", "execution", "matching", "market", "surveillance", "trading"],
    classification: "venue",
    riskTier: "HIGH",
    modeBinding: "VENUE",
    watermarkPolicy: "FORENSIC",
    exportPolicy: "PDF_ONLY",
  },
  {
    keywords: ["risk", "failure", "incident", "disaster", "continuity", "stress"],
    classification: "risk",
    riskTier: "HIGH",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "FORENSIC",
    exportPolicy: "PDF_ONLY",
  },
  {
    keywords: ["governance", "charter", "board", "resolution", "bylaw", "policy"],
    classification: "governance",
    riskTier: "HIGH",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "STANDARD",
    exportPolicy: "PDF_PASSWORD",
  },
  {
    keywords: ["patent", "trademark", "source code", "architecture", "whitepaper", "intellectual property"],
    classification: "ip",
    riskTier: "CRITICAL",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "MAXIMUM",
    exportPolicy: "VIEW_ONLY",
  },
  {
    keywords: ["research", "genesis", "protocol", "experiment", "simulation"],
    classification: "research",
    riskTier: "HIGH",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "STANDARD",
    exportPolicy: "PDF_ONLY",
  },
  {
    keywords: ["invoice", "receipt", "operational", "checklist", "procedure"],
    classification: "operational",
    riskTier: "LOW",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "STANDARD",
    exportPolicy: "PDF_ONLY",
  },
  {
    keywords: ["overview", "guide", "press", "public", "disclosure"],
    classification: "public",
    riskTier: "LOW",
    modeBinding: "CROSS-MODE",
    watermarkPolicy: "NONE",
    exportPolicy: "FULL",
  },
];

// ── Confidentiality Notices ──────────────────────────────────

const CONFIDENTIALITY_NOTICES: Record<RiskTier, string> = {
  LOW: "This document is the property of FTH Trading Inc. Distribution is limited to authorized recipients.",
  HIGH: "CONFIDENTIAL — This document contains proprietary information of FTH Trading Inc. Unauthorized disclosure, reproduction, or distribution is strictly prohibited. This document is individually watermarked and all access is logged.",
  CRITICAL: "RESTRICTED — CRITICAL SENSITIVITY — This document contains material non-public information and trade secrets of FTH Trading Inc. Any unauthorized access, disclosure, reproduction, or distribution is strictly prohibited and may result in civil and criminal penalties. This document is forensically fingerprinted, individually watermarked, and all access is monitored in real time.",
};

// ── Default Access Policies ──────────────────────────────────

const DEFAULT_ACCESS_POLICIES: Record<RiskTier, AccessPolicy> = {
  LOW: {
    allowedRoles: ["admin", "operator", "viewer"],
    allowedEntities: [],
    maxViewsPerRecipient: 100,
    linkExpiryHours: 720, // 30 days
    requireOTP: false,
    requireDeviceBinding: false,
    geoRestrictions: [],
    ipAllowlist: [],
    reauthTimeoutMinutes: 60,
  },
  HIGH: {
    allowedRoles: ["admin", "operator"],
    allowedEntities: [],
    maxViewsPerRecipient: 25,
    linkExpiryHours: 168, // 7 days
    requireOTP: true,
    requireDeviceBinding: false,
    geoRestrictions: [],
    ipAllowlist: [],
    reauthTimeoutMinutes: 30,
  },
  CRITICAL: {
    allowedRoles: ["admin"],
    allowedEntities: [],
    maxViewsPerRecipient: 10,
    linkExpiryHours: 24,
    requireOTP: true,
    requireDeviceBinding: true,
    geoRestrictions: ["US"],
    ipAllowlist: [],
    reauthTimeoutMinutes: 15,
  },
};

// ── Store ────────────────────────────────────────────────────

interface IntakeStore {
  records: IntakeRecord[];
  lastUpdated: string;
}

const STORE_DIR = path.join(process.cwd(), ".doc-engine");
const STORE_PATH = path.join(STORE_DIR, "sdc-intake.json");

function loadStore(): IntakeStore {
  if (fs.existsSync(STORE_PATH)) {
    return JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
  }
  return { records: [], lastUpdated: new Date().toISOString() };
}

function saveStore(store: IntakeStore): void {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  store.lastUpdated = new Date().toISOString();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), "utf-8");
}

// ── Document Intake Engine ───────────────────────────────────

export class DocumentIntakeEngine {
  private store: IntakeStore;

  constructor() {
    this.store = loadStore();
  }

  /**
   * Intake a document — classify, risk-tier, assign policies.
   * Nothing enters the SDC without passing through here.
   */
  intake(params: {
    documentId: string;
    documentTitle: string;
    documentHash: string;
    sku?: string;
    owner: { name: string; email: string; entity?: string };
    /** Override auto-classification */
    classification?: DocumentClassification;
    /** Override auto risk tier */
    riskTier?: RiskTier;
    /** Override mode binding */
    modeBinding?: SystemMode;
    /** Override watermark policy */
    watermarkPolicy?: WatermarkPolicy;
    /** Override export policy */
    exportPolicy?: ExportPolicy;
    /** Custom access policy overrides */
    accessPolicyOverrides?: Partial<AccessPolicy>;
    /** Raw document text for auto-classification */
    documentText?: string;
  }): IntakeRecord {
    // Auto-classify if not specified
    const autoResult = this.autoClassify(
      params.documentTitle,
      params.documentText || ""
    );

    const classification = params.classification || autoResult.classification;
    const riskTier = params.riskTier || autoResult.riskTier;
    const modeBinding = params.modeBinding || autoResult.modeBinding;
    const watermarkPolicy = params.watermarkPolicy || autoResult.watermarkPolicy;
    const exportPolicy = params.exportPolicy || autoResult.exportPolicy;

    // Build access policy
    const basePolicy = DEFAULT_ACCESS_POLICIES[riskTier];
    const accessPolicy: AccessPolicy = {
      ...basePolicy,
      ...params.accessPolicyOverrides,
    };

    const intakeId = crypto.randomBytes(16).toString("hex");
    const now = new Date().toISOString();

    const record: IntakeRecord = {
      intakeId,
      documentId: params.documentId,
      documentTitle: params.documentTitle,
      documentHash: params.documentHash,
      sku: params.sku,
      classification,
      riskTier,
      modeBinding,
      owner: params.owner,
      accessPolicy,
      watermarkPolicy,
      exportPolicy,
      state: "DRAFT",
      stateHistory: [],
      confidentialityNotice: CONFIDENTIALITY_NOTICES[riskTier],
      trackingEnabled: riskTier !== "LOW",
      createdAt: now,
      updatedAt: now,
      intakeHash: "",
    };

    record.intakeHash = this.computeHash(record);

    this.store.records.push(record);
    saveStore(this.store);

    return record;
  }

  /**
   * Advance document state.
   */
  advanceState(
    documentId: string,
    newState: DocumentState,
    actor: string,
    reason?: string
  ): IntakeRecord | null {
    const record = this.store.records.find((r) => r.documentId === documentId);
    if (!record) return null;

    // Validate state transitions
    const validTransitions: Record<DocumentState, DocumentState[]> = {
      DRAFT: ["INTERNAL", "REVOKED"],
      INTERNAL: ["EXTERNAL_VIEW", "SIGNED", "LOCKED", "REVOKED"],
      EXTERNAL_VIEW: ["SIGNED", "LOCKED", "REVOKED"],
      SIGNED: ["LOCKED", "ARCHIVED", "REVOKED"],
      LOCKED: ["ARCHIVED", "REVOKED"],
      ARCHIVED: ["REVOKED"],
      REVOKED: [], // Terminal state
    };

    const allowed = validTransitions[record.state];
    if (!allowed.includes(newState)) {
      return null;
    }

    record.stateHistory.push({
      from: record.state,
      to: newState,
      timestamp: new Date().toISOString(),
      actor,
      reason,
    });

    record.state = newState;
    record.updatedAt = new Date().toISOString();
    record.intakeHash = this.computeHash(record);

    saveStore(this.store);
    return record;
  }

  /**
   * Revoke a document — immediately invalidates all access tokens.
   */
  revoke(documentId: string, actor: string, reason: string): IntakeRecord | null {
    return this.advanceState(documentId, "REVOKED", actor, reason);
  }

  /**
   * Get intake record by document ID.
   */
  getByDocumentId(documentId: string): IntakeRecord | null {
    return this.store.records.find((r) => r.documentId === documentId) || null;
  }

  /**
   * Get intake record by intake ID.
   */
  getByIntakeId(intakeId: string): IntakeRecord | null {
    return this.store.records.find((r) => r.intakeId === intakeId) || null;
  }

  /**
   * Get all records by classification.
   */
  getByClassification(classification: DocumentClassification): IntakeRecord[] {
    return this.store.records.filter((r) => r.classification === classification);
  }

  /**
   * Get all records by risk tier.
   */
  getByRiskTier(riskTier: RiskTier): IntakeRecord[] {
    return this.store.records.filter((r) => r.riskTier === riskTier);
  }

  /**
   * Get all records by state.
   */
  getByState(state: DocumentState): IntakeRecord[] {
    return this.store.records.filter((r) => r.state === state);
  }

  /**
   * Get statistics.
   */
  getStats(): {
    total: number;
    byClassification: Record<string, number>;
    byRiskTier: Record<string, number>;
    byState: Record<string, number>;
    byMode: Record<string, number>;
  } {
    const byClassification: Record<string, number> = {};
    const byRiskTier: Record<string, number> = {};
    const byState: Record<string, number> = {};
    const byMode: Record<string, number> = {};

    for (const r of this.store.records) {
      byClassification[r.classification] = (byClassification[r.classification] || 0) + 1;
      byRiskTier[r.riskTier] = (byRiskTier[r.riskTier] || 0) + 1;
      byState[r.state] = (byState[r.state] || 0) + 1;
      byMode[r.modeBinding] = (byMode[r.modeBinding] || 0) + 1;
    }

    return {
      total: this.store.records.length,
      byClassification,
      byRiskTier,
      byState,
      byMode,
    };
  }

  /**
   * Check if a recipient is authorized to access a document.
   */
  isAuthorized(
    documentId: string,
    recipientId: string,
    recipientRoles: string[],
    ip?: string
  ): { authorized: boolean; reason: string } {
    const record = this.getByDocumentId(documentId);
    if (!record) return { authorized: false, reason: "Document not found in SDC" };
    if (record.state === "REVOKED") return { authorized: false, reason: "Document has been revoked" };
    if (record.state === "DRAFT") return { authorized: false, reason: "Document is in draft state" };

    // Check role authorization
    const hasRole = recipientRoles.some((role) =>
      record.accessPolicy.allowedRoles.includes(role)
    );
    const isEntity = record.accessPolicy.allowedEntities.length === 0 ||
      record.accessPolicy.allowedEntities.includes(recipientId);

    if (!hasRole && !isEntity) {
      return { authorized: false, reason: "Insufficient role or entity authorization" };
    }

    // Check IP allowlist
    if (record.accessPolicy.ipAllowlist.length > 0 && ip) {
      if (!record.accessPolicy.ipAllowlist.includes(ip)) {
        return { authorized: false, reason: "IP address not in allowlist" };
      }
    }

    return { authorized: true, reason: "Access granted" };
  }

  /**
   * Auto-classify a document based on title and content keywords.
   */
  private autoClassify(
    title: string,
    text: string
  ): {
    classification: DocumentClassification;
    riskTier: RiskTier;
    modeBinding: SystemMode;
    watermarkPolicy: WatermarkPolicy;
    exportPolicy: ExportPolicy;
  } {
    const combined = `${title} ${text}`.toLowerCase();
    let bestMatch: ClassificationRule | null = null;
    let bestScore = 0;

    for (const rule of CLASSIFICATION_RULES) {
      let score = 0;
      for (const kw of rule.keywords) {
        if (combined.includes(kw.toLowerCase())) {
          score++;
        }
      }
      if (score > bestScore) {
        bestScore = score;
        bestMatch = rule;
      }
    }

    if (bestMatch && bestScore > 0) {
      return {
        classification: bestMatch.classification,
        riskTier: bestMatch.riskTier,
        modeBinding: bestMatch.modeBinding,
        watermarkPolicy: bestMatch.watermarkPolicy,
        exportPolicy: bestMatch.exportPolicy,
      };
    }

    // Default: operational, LOW risk
    return {
      classification: "operational",
      riskTier: "LOW",
      modeBinding: "CROSS-MODE",
      watermarkPolicy: "STANDARD",
      exportPolicy: "PDF_ONLY",
    };
  }

  /**
   * Compute hash of an intake record.
   */
  private computeHash(record: IntakeRecord): string {
    const payload = [
      record.intakeId,
      record.documentId,
      record.documentHash,
      record.classification,
      record.riskTier,
      record.modeBinding,
      record.state,
      record.owner.email,
      record.createdAt,
    ].join(":");
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  /**
   * Format a summary report.
   */
  formatSummary(record: IntakeRecord): string {
    const lines: string[] = [
      `═══ SECURE DOCUMENT CONTROL — INTAKE RECORD ═══`,
      ``,
      `  Intake ID:       ${record.intakeId.substring(0, 16)}...`,
      `  Document ID:     ${record.documentId.substring(0, 16)}...`,
      `  Title:           ${record.documentTitle}`,
      `  SKU:             ${record.sku || "—"}`,
      `  Classification:  ${record.classification.toUpperCase()}`,
      `  Risk Tier:       ${record.riskTier}`,
      `  Mode Binding:    ${record.modeBinding}`,
      `  State:           ${record.state}`,
      `  Owner:           ${record.owner.name} <${record.owner.email}>`,
      `  Watermark:       ${record.watermarkPolicy}`,
      `  Export:          ${record.exportPolicy}`,
      `  Tracking:        ${record.trackingEnabled ? "ENABLED" : "DISABLED"}`,
      `  OTP Required:    ${record.accessPolicy.requireOTP ? "YES" : "NO"}`,
      `  Device Binding:  ${record.accessPolicy.requireDeviceBinding ? "YES" : "NO"}`,
      `  Link Expiry:     ${record.accessPolicy.linkExpiryHours}h`,
      `  Max Views:       ${record.accessPolicy.maxViewsPerRecipient}`,
      `  Created:         ${record.createdAt}`,
      `  Hash:            ${record.intakeHash.substring(0, 16)}...`,
      ``,
      `  ${record.confidentialityNotice}`,
      ``,
    ];
    return lines.join("\n");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _intakeEngine: DocumentIntakeEngine | null = null;

export function getDocumentIntakeEngine(): DocumentIntakeEngine {
  if (!_intakeEngine) {
    _intakeEngine = new DocumentIntakeEngine();
  }
  return _intakeEngine;
}
