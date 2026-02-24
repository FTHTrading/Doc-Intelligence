// ─────────────────────────────────────────────────────────────
// Document Lifecycle Registry — State Transition Tracker
//
// Tracks every document from draft → compliance → signed →
// anchored through a persistent registry with full hash chain.
//
// Every stage transition is recorded with:
//   • Stage hash (content at that stage)
//   • Transition timestamp
//   • Actor who triggered the transition
//   • Evidence hash (proof of transition legitimacy)
//
// This replaces flat CID-only tracking with lifecycle awareness.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

/** Document lifecycle stages (ordered) */
export type LifecycleStage =
  | "ingested"
  | "parsed"
  | "canonicalized"
  | "compliance-injected"
  | "signed"
  | "encrypted"
  | "anchored"
  | "registered"
  | "archived"
  | "superseded";

/** A single lifecycle entry, recording one stage transition */
export interface LifecycleTransition {
  /** Stage the document entered */
  stage: LifecycleStage;
  /** SHA-256 of document content at this stage */
  contentHash: string;
  /** Canonical hash (from canonicalizer) at this stage */
  canonicalHash?: string;
  /** Merkle root at this stage */
  merkleRoot?: string;
  /** CID if pushed to IPFS at this stage */
  cid?: string;
  /** Transaction hash if anchored on-chain */
  ledgerTx?: string;
  /** Chain used for anchoring */
  chain?: string;
  /** Block height of ledger confirmation */
  blockHeight?: number;
  /** Actor who triggered this transition */
  actor: string;
  /** Evidence supporting this transition */
  evidence?: string;
  /** ISO timestamp */
  timestamp: string;
}

/** Full document lifecycle record */
export interface DocumentLifecycle {
  /** Unique document ID */
  documentId: string;
  /** Document SKU (sovereign identity code) */
  sku: string;
  /** Original source filename */
  sourceFile: string;
  /** Document title */
  title: string;
  /** Current lifecycle stage */
  currentStage: LifecycleStage;
  /** Version number (increments on amendment) */
  version: number;
  /** Draft-stage content hash */
  draftHash: string;
  /** Post-compliance content hash */
  complianceHash?: string;
  /** Post-signature content hash */
  signedHash?: string;
  /** Canonical hash (deterministic) */
  canonicalHash?: string;
  /** Merkle root (deterministic) */
  merkleRoot?: string;
  /** Encrypted CID (if encrypted IPFS) */
  encryptedCID?: string;
  /** Plain CID (if standard IPFS) */
  plainCID?: string;
  /** Ledger transaction hash */
  ledgerTx?: string;
  /** Ledger chain name */
  ledgerChain?: string;
  /** Ledger block height */
  ledgerBlockHeight?: number;
  /** Hash of previous version (for amendment chain) */
  previousVersionHash?: string;
  /** Previous version document ID */
  previousVersionId?: string;
  /** Signature certificate hash */
  signatureCertificateHash?: string;
  /** All stage transitions (full audit trail) */
  transitions: LifecycleTransition[];
  /** Created ISO timestamp */
  createdAt: string;
  /** Last transition ISO timestamp */
  lastTransitionAt: string;
  /** Finalized ISO timestamp (null if not yet final) */
  finalizedAt?: string;
  /** Lifecycle record hash (self-integrity) */
  recordHash: string;
}

/** Lifecycle registry statistics */
export interface LifecycleStats {
  totalDocuments: number;
  byStage: Record<LifecycleStage, number>;
  byVersion: Record<number, number>;
  totalTransitions: number;
  averageTransitionsPerDoc: number;
  oldestDocument: string;
  newestDocument: string;
  /** Documents with ANY sovereign marker (signed, encrypted, or anchored) */
  securedCount: number;
  anchoredCount: number;
  signedCount: number;
  encryptedCount: number;
}

/** Deep integrity verification report */
export interface IntegrityReport {
  /** Overall pass/fail */
  valid: boolean;
  /** Record hash matches recomputation */
  recordHashValid: boolean;
  /** Stage transitions follow correct order with monotonic timestamps */
  stageChainValid: boolean;
  /** Hash chain is continuous (draft → compliance → signed → etc.) */
  hashContinuityValid: boolean;
  /** CIDs are consistent (plain vs encrypted, transitions reference them) */
  cidConsistencyValid: boolean;
  /** Signature certificate is bound to a signed hash */
  signatureBindingValid: boolean;
  /** List of specific issues found */
  issues: string[];
}

// ── Persistence Store ────────────────────────────────────────

interface LifecycleStore {
  engine: string;
  version: string;
  createdAt: string;
  lastUpdated: string;
  records: DocumentLifecycle[];
}

const LIFECYCLE_FILE = "lifecycle-registry.json";

// ── Lifecycle Registry Class ─────────────────────────────────

export class LifecycleRegistry {
  private store: LifecycleStore;
  private registryPath: string;

  constructor(registryDir: string = ".doc-engine") {
    if (!fs.existsSync(registryDir)) {
      fs.mkdirSync(registryDir, { recursive: true });
    }
    this.registryPath = path.join(registryDir, LIFECYCLE_FILE);
    this.store = this.load();
  }

  // ── CRUD ───────────────────────────────────────────────────

  /**
   * Create a new lifecycle record for a document.
   */
  createLifecycle(params: {
    documentId: string;
    sku: string;
    sourceFile: string;
    title: string;
    draftHash: string;
    canonicalHash?: string;
    merkleRoot?: string;
    actor: string;
    previousVersionId?: string;
    previousVersionHash?: string;
  }): DocumentLifecycle {
    // Check for duplicate
    const existing = this.store.records.find(
      (r) => r.documentId === params.documentId
    );
    if (existing) {
      return existing; // idempotent
    }

    const now = new Date().toISOString();
    const version = params.previousVersionId
      ? (this.getLifecycle(params.previousVersionId)?.version || 0) + 1
      : 1;

    const record: DocumentLifecycle = {
      documentId: params.documentId,
      sku: params.sku,
      sourceFile: params.sourceFile,
      title: params.title,
      currentStage: "ingested",
      version,
      draftHash: params.draftHash,
      canonicalHash: params.canonicalHash,
      merkleRoot: params.merkleRoot,
      previousVersionHash: params.previousVersionHash,
      previousVersionId: params.previousVersionId,
      transitions: [
        {
          stage: "ingested",
          contentHash: params.draftHash,
          canonicalHash: params.canonicalHash,
          merkleRoot: params.merkleRoot,
          actor: params.actor,
          timestamp: now,
        },
      ],
      createdAt: now,
      lastTransitionAt: now,
      recordHash: "", // computed below
    };

    record.recordHash = this.computeRecordHash(record);
    this.store.records.push(record);
    this.save();

    return record;
  }

  /**
   * Advance a document to the next lifecycle stage.
   */
  advanceStage(
    documentId: string,
    stage: LifecycleStage,
    params: {
      contentHash: string;
      canonicalHash?: string;
      merkleRoot?: string;
      cid?: string;
      ledgerTx?: string;
      chain?: string;
      blockHeight?: number;
      actor: string;
      evidence?: string;
    }
  ): DocumentLifecycle {
    const record = this.getLifecycle(documentId);
    if (!record) {
      throw new Error(`Lifecycle not found for document: ${documentId}`);
    }

    const transition: LifecycleTransition = {
      stage,
      contentHash: params.contentHash,
      canonicalHash: params.canonicalHash,
      merkleRoot: params.merkleRoot,
      cid: params.cid,
      ledgerTx: params.ledgerTx,
      chain: params.chain,
      blockHeight: params.blockHeight,
      actor: params.actor,
      evidence: params.evidence,
      timestamp: new Date().toISOString(),
    };

    record.transitions.push(transition);
    record.currentStage = stage;
    record.lastTransitionAt = transition.timestamp;

    // Update top-level fields based on stage
    switch (stage) {
      case "compliance-injected":
        record.complianceHash = params.contentHash;
        break;
      case "signed":
        record.signedHash = params.contentHash;
        break;
      case "canonicalized":
        record.canonicalHash = params.canonicalHash || params.contentHash;
        record.merkleRoot = params.merkleRoot;
        break;
      case "encrypted":
        record.encryptedCID = params.cid;
        break;
      case "anchored":
        record.plainCID = record.plainCID || params.cid;
        record.ledgerTx = params.ledgerTx;
        record.ledgerChain = params.chain;
        record.ledgerBlockHeight = params.blockHeight;
        break;
      case "registered":
        record.plainCID = record.plainCID || params.cid;
        break;
      case "archived":
        record.finalizedAt = transition.timestamp;
        break;
    }

    // Recompute record integrity hash
    record.recordHash = this.computeRecordHash(record);
    this.save();

    return record;
  }

  /**
   * Get a lifecycle record by document ID.
   */
  getLifecycle(documentId: string): DocumentLifecycle | undefined {
    return this.store.records.find((r) => r.documentId === documentId);
  }

  /**
   * Get a lifecycle record by SKU.
   */
  getLifecycleBySKU(sku: string): DocumentLifecycle | undefined {
    return this.store.records.find((r) => r.sku === sku);
  }

  /**
   * Update SKU on an existing lifecycle record.
   */
  updateSKU(documentId: string, sku: string): void {
    const record = this.getLifecycle(documentId);
    if (record) {
      record.sku = sku;
      record.recordHash = this.computeRecordHash(record);
      this.save();
    }
  }

  /**
   * Get all lifecycle records.
   */
  getAllLifecycles(): DocumentLifecycle[] {
    return [...this.store.records];
  }

  /**
   * Get the version chain for a document (all versions).
   */
  getVersionChain(documentId: string): DocumentLifecycle[] {
    const chain: DocumentLifecycle[] = [];
    let current = this.getLifecycle(documentId);

    while (current) {
      chain.unshift(current); // prepend (oldest first)
      if (current.previousVersionId) {
        current = this.getLifecycle(current.previousVersionId);
      } else {
        break;
      }
    }

    return chain;
  }

  // ── Integrity ──────────────────────────────────────────────

  /** Ordered stage precedence for chain validation */
  private static readonly STAGE_ORDER: LifecycleStage[] = [
    "ingested", "parsed", "canonicalized", "compliance-injected",
    "signed", "encrypted", "anchored", "registered", "archived", "superseded",
  ];

  /**
   * Deep integrity verification: stage chain, hash continuity,
   * CID consistency, signature binding, record hash.
   */
  verifyIntegrity(documentId: string): IntegrityReport {
    const record = this.getLifecycle(documentId);
    if (!record) {
      return {
        valid: false,
        recordHashValid: false,
        stageChainValid: false,
        hashContinuityValid: false,
        cidConsistencyValid: false,
        signatureBindingValid: false,
        issues: ["Record not found"],
      };
    }

    const issues: string[] = [];

    // ── 1. Record Hash ──
    const expectedHash = this.computeRecordHash(record);
    const recordHashValid = record.recordHash === expectedHash;
    if (!recordHashValid) {
      issues.push(`Record hash tampered: expected ${expectedHash.substring(0, 16)}..., got ${record.recordHash.substring(0, 16)}...`);
    }

    // ── 2. Stage Chain Order ──
    let stageChainValid = true;
    let lastStageIndex = -1;
    for (let i = 0; i < record.transitions.length; i++) {
      const t = record.transitions[i];
      const idx = LifecycleRegistry.STAGE_ORDER.indexOf(t.stage);
      if (idx === -1) {
        stageChainValid = false;
        issues.push(`Transition ${i}: unknown stage "${t.stage}"`);
      } else if (idx < lastStageIndex) {
        stageChainValid = false;
        issues.push(`Transition ${i}: stage "${t.stage}" (${idx}) regresses from previous index (${lastStageIndex})`);
      }
      lastStageIndex = idx;
    }

    // Verify timestamps are monotonically increasing
    for (let i = 1; i < record.transitions.length; i++) {
      const prev = new Date(record.transitions[i - 1].timestamp).getTime();
      const curr = new Date(record.transitions[i].timestamp).getTime();
      if (curr < prev) {
        stageChainValid = false;
        issues.push(`Transition ${i}: timestamp regression (${record.transitions[i].timestamp} < ${record.transitions[i - 1].timestamp})`);
      }
    }

    // ── 3. Hash Continuity ──
    let hashContinuityValid = true;

    // Draft hash should match the first transition's content hash
    if (record.transitions.length > 0 && record.draftHash !== record.transitions[0].contentHash) {
      hashContinuityValid = false;
      issues.push(`Draft hash does not match first transition content hash`);
    }

    // Each transition should have a non-empty content hash
    for (let i = 0; i < record.transitions.length; i++) {
      if (!record.transitions[i].contentHash) {
        hashContinuityValid = false;
        issues.push(`Transition ${i}: missing content hash`);
      }
    }

    // If record has signedHash, a "signed" transition must exist
    if (record.signedHash) {
      const signedTransition = record.transitions.find(t => t.stage === "signed");
      if (!signedTransition) {
        hashContinuityValid = false;
        issues.push(`signedHash present but no "signed" stage transition`);
      }
    }

    // ── 4. CID Consistency ──
    let cidConsistencyValid = true;

    // If plainCID is set, an IPFS-related transition should reference it
    if (record.plainCID) {
      const hasCIDTransition = record.transitions.some(t => t.cid === record.plainCID);
      if (!hasCIDTransition) {
        cidConsistencyValid = false;
        issues.push(`plainCID "${record.plainCID}" not referenced in any transition`);
      }
    }

    // If encryptedCID is set, it should differ from plainCID
    if (record.encryptedCID && record.plainCID && record.encryptedCID === record.plainCID) {
      cidConsistencyValid = false;
      issues.push(`encryptedCID and plainCID are identical — encryption may not have occurred`);
    }

    // If ledgerTx is set, an "anchored" transition should exist
    if (record.ledgerTx) {
      const anchoredTransition = record.transitions.find(t => t.stage === "anchored");
      if (!anchoredTransition) {
        cidConsistencyValid = false;
        issues.push(`ledgerTx present but no "anchored" stage transition`);
      }
    }

    // ── 5. Signature Binding ──
    let signatureBindingValid = true;

    // If signatureCertificateHash exists, signedHash should also exist
    if (record.signatureCertificateHash && !record.signedHash) {
      signatureBindingValid = false;
      issues.push(`Signature certificate hash present but no signedHash — unbound certificate`);
    }

    // currentStage should match the last transition's stage
    if (record.transitions.length > 0) {
      const lastTransitionStage = record.transitions[record.transitions.length - 1].stage;
      if (record.currentStage !== lastTransitionStage) {
        issues.push(`currentStage "${record.currentStage}" does not match last transition stage "${lastTransitionStage}"`);
        stageChainValid = false;
      }
    }

    const valid = recordHashValid && stageChainValid && hashContinuityValid && cidConsistencyValid && signatureBindingValid;

    return {
      valid,
      recordHashValid,
      stageChainValid,
      hashContinuityValid,
      cidConsistencyValid,
      signatureBindingValid,
      issues,
    };
  }

  /**
   * Verify integrity of ALL records in the registry.
   */
  verifyAllIntegrity(): { valid: boolean; failures: string[]; reports: IntegrityReport[] } {
    const failures: string[] = [];
    const reports: IntegrityReport[] = [];
    for (const record of this.store.records) {
      const report = this.verifyIntegrity(record.documentId);
      reports.push(report);
      if (!report.valid) {
        failures.push(
          `${record.documentId} (${record.sku}): ${report.issues.join("; ")}`
        );
      }
    }
    return { valid: failures.length === 0, failures, reports };
  }

  // ── Statistics ─────────────────────────────────────────────

  /**
   * Get registry statistics.
   */
  getStats(): LifecycleStats {
    const records = this.store.records;
    const byStage: Record<string, number> = {};
    const byVersion: Record<number, number> = {};
    let totalTransitions = 0;
    let anchoredCount = 0;
    let signedCount = 0;
    let encryptedCount = 0;
    let securedCount = 0;

    for (const r of records) {
      byStage[r.currentStage] = (byStage[r.currentStage] || 0) + 1;
      byVersion[r.version] = (byVersion[r.version] || 0) + 1;
      totalTransitions += r.transitions.length;
      const isAnchored = !!r.ledgerTx;
      const isSigned = !!r.signedHash;
      const isEncrypted = !!r.encryptedCID;
      if (isAnchored) anchoredCount++;
      if (isSigned) signedCount++;
      if (isEncrypted) encryptedCount++;
      // A document is "secured" if it has ANY sovereign marker
      if (isAnchored || isSigned || isEncrypted) securedCount++;
    }

    const sorted = [...records].sort(
      (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
    );

    return {
      totalDocuments: records.length,
      byStage: byStage as Record<LifecycleStage, number>,
      byVersion: byVersion as Record<number, number>,
      totalTransitions,
      averageTransitionsPerDoc: records.length > 0 ? totalTransitions / records.length : 0,
      oldestDocument: sorted[0]?.createdAt || "",
      newestDocument: sorted[sorted.length - 1]?.createdAt || "",
      securedCount,
      anchoredCount,
      signedCount,
      encryptedCount,
    };
  }

  /**
   * Generate a human-readable lifecycle report for a document.
   */
  generateReport(documentId: string): string {
    const record = this.getLifecycle(documentId);
    if (!record) return `No lifecycle record found for: ${documentId}`;

    const lines: string[] = [];
    lines.push(`╔══════════════════════════════════════════════════════╗`);
    lines.push(`║  DOCUMENT LIFECYCLE REPORT                          ║`);
    lines.push(`╚══════════════════════════════════════════════════════╝`);
    lines.push(``);
    lines.push(`  Document: ${record.title}`);
    lines.push(`  SKU: ${record.sku}`);
    lines.push(`  ID: ${record.documentId.substring(0, 16)}...`);
    lines.push(`  Version: ${record.version}`);
    lines.push(`  Current Stage: ${record.currentStage.toUpperCase()}`);
    lines.push(`  Source: ${record.sourceFile}`);
    lines.push(``);
    lines.push(`  ─── Hash Chain ───────────────────────────────────`);
    lines.push(`  Draft Hash:      ${record.draftHash.substring(0, 32)}...`);
    if (record.complianceHash) lines.push(`  Compliance Hash: ${record.complianceHash.substring(0, 32)}...`);
    if (record.signedHash) lines.push(`  Signed Hash:     ${record.signedHash.substring(0, 32)}...`);
    if (record.canonicalHash) lines.push(`  Canonical Hash:  ${record.canonicalHash.substring(0, 32)}...`);
    if (record.merkleRoot) lines.push(`  Merkle Root:     ${record.merkleRoot.substring(0, 32)}...`);
    lines.push(``);
    lines.push(`  ─── Anchoring ────────────────────────────────────`);
    if (record.plainCID) lines.push(`  IPFS CID:        ${record.plainCID}`);
    if (record.encryptedCID) lines.push(`  Encrypted CID:   ${record.encryptedCID}`);
    if (record.ledgerTx) lines.push(`  Ledger TX:       ${record.ledgerTx}`);
    if (record.ledgerChain) lines.push(`  Chain:           ${record.ledgerChain}`);
    if (record.ledgerBlockHeight) lines.push(`  Block Height:    ${record.ledgerBlockHeight}`);
    lines.push(``);
    lines.push(`  ─── Transitions (${record.transitions.length}) ─────────────────────`);
    for (const t of record.transitions) {
      lines.push(`  [${t.timestamp}] ${t.stage.toUpperCase()} by ${t.actor}`);
      lines.push(`    Hash: ${t.contentHash.substring(0, 24)}...`);
      if (t.cid) lines.push(`    CID: ${t.cid}`);
      if (t.ledgerTx) lines.push(`    TX: ${t.ledgerTx}`);
    }
    lines.push(``);
    lines.push(`  Record Integrity: ${record.recordHash.substring(0, 24)}...`);
    lines.push(``);

    return lines.join("\n");
  }

  // ── Private ────────────────────────────────────────────────

  private computeRecordHash(record: DocumentLifecycle): string {
    const payload = {
      documentId: record.documentId,
      sku: record.sku,
      version: record.version,
      draftHash: record.draftHash,
      transitions: record.transitions.map((t) => ({
        stage: t.stage,
        contentHash: t.contentHash,
        timestamp: t.timestamp,
      })),
    };
    return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  }

  private load(): LifecycleStore {
    if (fs.existsSync(this.registryPath)) {
      try {
        const raw = fs.readFileSync(this.registryPath, "utf-8");
        return JSON.parse(raw) as LifecycleStore;
      } catch {
        console.warn("[LIFECYCLE] Corrupt registry — creating new one");
      }
    }
    return {
      engine: "Document Intelligence Engine",
      version: "4.0.0",
      createdAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      records: [],
    };
  }

  private save(): void {
    this.store.lastUpdated = new Date().toISOString();
    fs.writeFileSync(this.registryPath, JSON.stringify(this.store, null, 2), "utf-8");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: LifecycleRegistry | null = null;

export function getLifecycleRegistry(storeDir?: string): LifecycleRegistry {
  if (!_instance) {
    _instance = new LifecycleRegistry(storeDir || ".doc-engine");
  }
  return _instance;
}
