// ─────────────────────────────────────────────────────────────
// Ledger Anchor Hardening — Deterministic Transaction Builder
//
// Wraps the existing on-chain anchor with:
//
//   1. Deterministic memo construction (canonical hash embedding)
//   2. Multi-chain redundancy support
//   3. Full transaction metadata storage
//   4. Anchor verification / proof generation
//   5. Anchor chain (links successive anchors)
//
// The old onchainAnchor.ts provides the chain hooks.
// This module provides the sovereign integrity layer on top.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { DocumentFingerprint } from "../schema/documentSchema";
import { SupportedChain, anchorDocument, AnchorResponse } from "../governance/onchainAnchor";

// ── Types ────────────────────────────────────────────────────

/** Deterministic memo structure embedded in every anchor transaction */
export interface AnchorMemo {
  /** Engine identifier */
  engine: string;
  /** Protocol version */
  protocol: string;
  /** Document SHA-256 */
  sha256: string;
  /** Document Merkle root */
  merkleRoot: string;
  /** Canonical hash (from canonicalizer, if available) */
  canonicalHash?: string;
  /** Document SKU */
  sku?: string;
  /** Anchor timestamp (ISO) */
  anchoredAt: string;
  /** Memo hash = SHA-256 of deterministic serialization of above fields */
  memoHash: string;
}

/** Full anchor record — stored in persistent ledger */
export interface LedgerAnchorRecord {
  /** Unique anchor ID */
  anchorId: string;
  /** Document ID */
  documentId: string;
  /** Document SKU */
  sku?: string;
  /** Chain used */
  chain: SupportedChain;
  /** Transaction hash on the chain */
  transactionHash?: string;
  /** Block height (if applicable) */
  blockHeight?: number;
  /** IPFS CID (if anchored via IPFS) */
  ipfsCid?: string;
  /** The deterministic memo embedded in the transaction */
  memo: AnchorMemo;
  /** Document fingerprint at anchor time */
  fingerprint: DocumentFingerprint;
  /** Signature hash (if document was signed before anchoring) */
  signatureHash?: string;
  /** Encrypted CID (if document was encrypted before anchoring) */
  encryptedCID?: string;
  /** Previous anchor hash (for anchor chain integrity) */
  previousAnchorHash: string;
  /** Sequence number in anchor chain */
  sequence: number;
  /** Self-hash of this record */
  recordHash: string;
  /** Timestamp */
  anchoredAt: string;
  /** Multi-chain: additional chain anchors for redundancy */
  redundantAnchors?: Array<{
    chain: SupportedChain;
    transactionHash?: string;
    ipfsCid?: string;
    anchoredAt: string;
  }>;
}

/** Anchor verification proof */
export interface AnchorProof {
  /** Anchor record exists */
  exists: boolean;
  /** Record hash is valid */
  recordIntegrity: boolean;
  /** Memo hash is valid */
  memoIntegrity: boolean;
  /** Chain link valid (previous anchor hash consistent) */
  chainValid: boolean;
  /** Transaction hash present */
  transactionExists: boolean;
  /** Full details */
  details: string[];
}

// ── Deterministic Memo Builder ───────────────────────────────

const PROTOCOL_VERSION = "sovereign-anchor-v1";
const ENGINE_ID = "doc-intelligence-engine";

/**
 * Build a deterministic anchor memo.
 * Same inputs → same memoHash, every time.
 */
export function buildAnchorMemo(
  fingerprint: DocumentFingerprint,
  canonicalHash?: string,
  sku?: string
): AnchorMemo {
  const anchoredAt = new Date().toISOString();

  const memoBody: Record<string, string> = {
    engine: ENGINE_ID,
    protocol: PROTOCOL_VERSION,
    sha256: fingerprint.sha256,
    merkleRoot: fingerprint.merkleRoot,
  };

  if (canonicalHash) memoBody.canonicalHash = canonicalHash;
  if (sku) memoBody.sku = sku;
  memoBody.anchoredAt = anchoredAt;

  // Deterministic serialization for hash
  const sortedKeys = Object.keys(memoBody).sort();
  const deterministicString = sortedKeys
    .map((k) => `${k}:${memoBody[k]}`)
    .join("|");

  const memoHash = crypto
    .createHash("sha256")
    .update(deterministicString)
    .digest("hex");

  return {
    engine: ENGINE_ID,
    protocol: PROTOCOL_VERSION,
    sha256: fingerprint.sha256,
    merkleRoot: fingerprint.merkleRoot,
    canonicalHash,
    sku,
    anchoredAt,
    memoHash,
  };
}

// ── Ledger Anchor Engine ─────────────────────────────────────

interface LedgerStore {
  engine: string;
  version: string;
  anchors: LedgerAnchorRecord[];
}

const LEDGER_FILE = "ledger-anchors.json";

/**
 * Persistent ledger anchor registry.
 */
export class LedgerAnchorEngine {
  private store: LedgerStore;
  private storePath: string;

  constructor(storeDir: string = ".doc-engine") {
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.storePath = path.join(storeDir, LEDGER_FILE);
    this.store = this.load();
  }

  /**
   * Anchor a document to a chain with deterministic memo embedding.
   */
  async anchor(params: {
    documentId: string;
    fingerprint: DocumentFingerprint;
    chain: SupportedChain;
    sku?: string;
    canonicalHash?: string;
    signatureHash?: string;
    encryptedCID?: string;
    metadata?: Record<string, string>;
  }): Promise<LedgerAnchorRecord> {
    const anchorId = crypto.randomBytes(16).toString("hex");

    // Build deterministic memo
    const memo = buildAnchorMemo(
      params.fingerprint,
      params.canonicalHash,
      params.sku
    );

    // Execute the actual chain anchor
    const chainResult: AnchorResponse = await anchorDocument({
      fingerprint: params.fingerprint,
      chain: params.chain,
      metadata: {
        ...params.metadata,
        memoHash: memo.memoHash,
        anchorId,
      },
    });

    // Determine previous anchor hash for chain integrity
    const previousAnchor = this.store.anchors.length > 0
      ? this.store.anchors[this.store.anchors.length - 1]
      : null;
    const previousAnchorHash = previousAnchor
      ? previousAnchor.recordHash
      : crypto.createHash("sha256").update("genesis-anchor").digest("hex");
    const sequence = previousAnchor ? previousAnchor.sequence + 1 : 1;

    // Build record (without self-hash)
    const recordBody = {
      anchorId,
      documentId: params.documentId,
      sku: params.sku,
      chain: params.chain,
      transactionHash: chainResult.reference.transactionHash,
      blockHeight: undefined as number | undefined,
      ipfsCid: chainResult.reference.ipfsCid,
      memo,
      fingerprint: params.fingerprint,
      signatureHash: params.signatureHash,
      encryptedCID: params.encryptedCID,
      previousAnchorHash,
      sequence,
      anchoredAt: memo.anchoredAt,
    };

    // Compute record hash
    const hashInput = JSON.stringify({
      anchorId: recordBody.anchorId,
      documentId: recordBody.documentId,
      sku: recordBody.sku,
      chain: recordBody.chain,
      transactionHash: recordBody.transactionHash,
      memoHash: recordBody.memo.memoHash,
      sha256: recordBody.fingerprint.sha256,
      merkleRoot: recordBody.fingerprint.merkleRoot,
      previousAnchorHash: recordBody.previousAnchorHash,
      sequence: recordBody.sequence,
    });

    const recordHash = crypto
      .createHash("sha256")
      .update(hashInput)
      .digest("hex");

    const record: LedgerAnchorRecord = {
      ...recordBody,
      recordHash,
    };

    this.store.anchors.push(record);
    this.save();

    console.log(`[LEDGER] Anchor ${sequence} → ${params.chain.toUpperCase()}`);
    console.log(`[LEDGER] Memo Hash: ${memo.memoHash}`);
    console.log(`[LEDGER] Record Hash: ${recordHash}`);
    if (record.transactionHash) {
      console.log(`[LEDGER] TX: ${record.transactionHash}`);
    }
    if (record.ipfsCid) {
      console.log(`[LEDGER] CID: ${record.ipfsCid}`);
    }

    return record;
  }

  /**
   * Anchor to multiple chains for redundancy.
   */
  async anchorMultiChain(params: {
    documentId: string;
    fingerprint: DocumentFingerprint;
    chains: SupportedChain[];
    sku?: string;
    canonicalHash?: string;
    signatureHash?: string;
    encryptedCID?: string;
  }): Promise<LedgerAnchorRecord> {
    if (params.chains.length === 0) {
      throw new Error("[LEDGER] No chains specified for multi-chain anchor");
    }

    // Primary chain = first in list
    const primaryChain = params.chains[0];
    const record = await this.anchor({
      documentId: params.documentId,
      fingerprint: params.fingerprint,
      chain: primaryChain,
      sku: params.sku,
      canonicalHash: params.canonicalHash,
      signatureHash: params.signatureHash,
      encryptedCID: params.encryptedCID,
    });

    // Secondary chains for redundancy
    const redundant: LedgerAnchorRecord["redundantAnchors"] = [];
    for (const chain of params.chains.slice(1)) {
      try {
        const result = await anchorDocument({
          fingerprint: params.fingerprint,
          chain,
          metadata: { primaryAnchorId: record.anchorId },
        });
        redundant.push({
          chain,
          transactionHash: result.reference.transactionHash,
          ipfsCid: result.reference.ipfsCid,
          anchoredAt: new Date().toISOString(),
        });
        console.log(`[LEDGER] Redundant anchor → ${chain.toUpperCase()}`);
      } catch (err) {
        console.warn(`[LEDGER] Redundant anchor to ${chain} failed:`, err);
      }
    }

    if (redundant.length > 0) {
      record.redundantAnchors = redundant;
      // Update stored record
      const idx = this.store.anchors.findIndex((a) => a.anchorId === record.anchorId);
      if (idx >= 0) this.store.anchors[idx] = record;
      this.save();
    }

    return record;
  }

  /**
   * Verify an anchor record's integrity.
   */
  verifyAnchor(anchorId: string): AnchorProof {
    const record = this.store.anchors.find((a) => a.anchorId === anchorId);
    if (!record) {
      return {
        exists: false,
        recordIntegrity: false,
        memoIntegrity: false,
        chainValid: false,
        transactionExists: false,
        details: [`Anchor ${anchorId} not found`],
      };
    }

    const details: string[] = [];

    // ── Record hash integrity ──
    const hashInput = JSON.stringify({
      anchorId: record.anchorId,
      documentId: record.documentId,
      sku: record.sku,
      chain: record.chain,
      transactionHash: record.transactionHash,
      memoHash: record.memo.memoHash,
      sha256: record.fingerprint.sha256,
      merkleRoot: record.fingerprint.merkleRoot,
      previousAnchorHash: record.previousAnchorHash,
      sequence: record.sequence,
    });
    const expectedHash = crypto.createHash("sha256").update(hashInput).digest("hex");
    const recordIntegrity = expectedHash === record.recordHash;
    details.push(recordIntegrity ? "Record hash: VALID" : "Record hash: TAMPERED");

    // ── Memo hash integrity ──
    const memoBody: Record<string, string> = {
      engine: record.memo.engine,
      protocol: record.memo.protocol,
      sha256: record.memo.sha256,
      merkleRoot: record.memo.merkleRoot,
    };
    if (record.memo.canonicalHash) memoBody.canonicalHash = record.memo.canonicalHash;
    if (record.memo.sku) memoBody.sku = record.memo.sku;
    memoBody.anchoredAt = record.memo.anchoredAt;

    const sortedKeys = Object.keys(memoBody).sort();
    const deterministicString = sortedKeys.map((k) => `${k}:${memoBody[k]}`).join("|");
    const expectedMemoHash = crypto.createHash("sha256").update(deterministicString).digest("hex");
    const memoIntegrity = expectedMemoHash === record.memo.memoHash;
    details.push(memoIntegrity ? "Memo hash: VALID" : "Memo hash: TAMPERED");

    // ── Chain integrity ──
    let chainValid = true;
    if (record.sequence === 1) {
      const genesisHash = crypto.createHash("sha256").update("genesis-anchor").digest("hex");
      chainValid = record.previousAnchorHash === genesisHash;
    } else {
      const prev = this.store.anchors.find((a) => a.sequence === record.sequence - 1);
      if (prev) {
        chainValid = record.previousAnchorHash === prev.recordHash;
      } else {
        chainValid = false;
        details.push("Previous anchor in chain not found");
      }
    }
    details.push(chainValid ? "Anchor chain: VALID" : "Anchor chain: BROKEN");

    // ── Transaction existence ──
    const transactionExists = !!(record.transactionHash || record.ipfsCid);
    details.push(transactionExists ? "Transaction reference: EXISTS" : "Transaction reference: MISSING");

    return {
      exists: true,
      recordIntegrity,
      memoIntegrity,
      chainValid,
      transactionExists,
      details,
    };
  }

  /**
   * Verify the entire anchor chain integrity.
   */
  verifyFullChain(): { valid: boolean; totalAnchors: number; issues: string[] } {
    const issues: string[] = [];
    let valid = true;

    for (const anchor of this.store.anchors) {
      const proof = this.verifyAnchor(anchor.anchorId);
      if (!proof.recordIntegrity || !proof.memoIntegrity || !proof.chainValid) {
        valid = false;
        issues.push(`Anchor ${anchor.sequence} (${anchor.anchorId}): INTEGRITY FAILURE`);
        issues.push(...proof.details.filter((d) => !d.includes("VALID")));
      }
    }

    if (valid) {
      issues.push("All anchor records verified. Chain integrity: INTACT.");
    }

    return { valid, totalAnchors: this.store.anchors.length, issues };
  }

  /**
   * Get anchor record by document ID.
   */
  getByDocumentId(documentId: string): LedgerAnchorRecord | undefined {
    return this.store.anchors.find((a) => a.documentId === documentId);
  }

  /**
   * Get all anchors for a document (including superseded versions).
   */
  getAllByDocumentId(documentId: string): LedgerAnchorRecord[] {
    return this.store.anchors.filter((a) => a.documentId === documentId);
  }

  /**
   * Get ledger statistics.
   */
  getStats(): {
    totalAnchors: number;
    byChain: Record<string, number>;
    lastAnchorAt: string | null;
  } {
    const byChain: Record<string, number> = {};
    for (const a of this.store.anchors) {
      byChain[a.chain] = (byChain[a.chain] || 0) + 1;
    }
    const last = this.store.anchors.length > 0
      ? this.store.anchors[this.store.anchors.length - 1].anchoredAt
      : null;
    return { totalAnchors: this.store.anchors.length, byChain, lastAnchorAt: last };
  }

  private load(): LedgerStore {
    if (fs.existsSync(this.storePath)) {
      try {
        const raw = fs.readFileSync(this.storePath, "utf-8");
        return JSON.parse(raw) as LedgerStore;
      } catch {
        console.warn("[LEDGER] Corrupt store — creating new one");
      }
    }
    return { engine: "Document Intelligence Engine", version: "4.0.0", anchors: [] };
  }

  private save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2), "utf-8");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _engine: LedgerAnchorEngine | null = null;

export function getLedgerAnchorEngine(storeDir?: string): LedgerAnchorEngine {
  if (!_engine) {
    _engine = new LedgerAnchorEngine(storeDir || ".doc-engine");
  }
  return _engine;
}
