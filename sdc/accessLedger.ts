// ─────────────────────────────────────────────────────────────
// Secure Document Control — Access Ledger
//
// Append-only, hash-chained audit ledger for all document
// access events. Every view, download, print, share, and
// authentication attempt is permanently recorded.
//
// Architecture:
//   - Follows VaultLedger / EventLog hash-chaining pattern
//   - Each entry links to the previous via SHA-256 chain hash
//   - Tamper detection via full chain integrity verification
//   - Forensic-grade timestamping and attribution
//   - Supports compliance queries by document, recipient, time
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

export type AccessAction =
  | "viewed"
  | "scrolled"
  | "downloaded"
  | "printed"
  | "shared"
  | "exported"
  | "copied"
  | "screenshot-detected"
  | "auth-success"
  | "auth-failed"
  | "otp-verified"
  | "otp-failed"
  | "device-bound"
  | "token-issued"
  | "token-revoked"
  | "token-expired"
  | "access-denied"
  | "watermark-applied"
  | "fingerprint-embedded"
  | "session-started"
  | "session-ended"
  | "state-changed"
  | "policy-enforced";

export interface AccessEntry {
  /** Unique entry ID */
  entryId: string;
  /** Sequence number (1-based, monotonic) */
  sequence: number;
  /** Document ID */
  documentId: string;
  /** Intake ID (links to DocumentIntakeEngine) */
  intakeId?: string;
  /** Access token ID */
  tokenId?: string;
  /** The action performed */
  action: AccessAction;
  /** Actor — recipient email or system actor */
  actor: string;
  /** Actor organization */
  organization?: string;
  /** ISO timestamp */
  timestamp: string;
  /** Client IP address */
  ipAddress?: string;
  /** Device fingerprint */
  deviceFingerprint?: string;
  /** User agent string */
  userAgent?: string;
  /** Geo location (if resolved) */
  geoLocation?: string;
  /** Details / description */
  details: string;
  /** Result: granted, denied, or info */
  result: "granted" | "denied" | "info";
  /** Denial reason (if denied) */
  denialReason?: string;
  /** Document hash at time of access */
  documentHash?: string;
  /** Watermark ID applied (if any) */
  watermarkId?: string;
  /** Export ID (if this was an export) */
  exportId?: string;
  /** Chain hash — SHA-256(entryId + documentId + action + timestamp + previousHash) */
  chainHash: string;
  /** Additional metadata */
  metadata: Record<string, string>;
}

export interface AccessQuery {
  /** Filter by document ID */
  documentId?: string;
  /** Filter by actor email */
  actor?: string;
  /** Filter by action type */
  action?: AccessAction;
  /** Filter by result */
  result?: "granted" | "denied" | "info";
  /** Filter events after this timestamp */
  after?: string;
  /** Filter events before this timestamp */
  before?: string;
  /** Filter by token ID */
  tokenId?: string;
  /** Max results */
  limit?: number;
}

export interface LedgerStats {
  totalEntries: number;
  uniqueDocuments: number;
  uniqueActors: number;
  actionCounts: Record<string, number>;
  denialCount: number;
  chainIntact: boolean;
  firstEntry: string;
  lastEntry: string;
}

export interface IntegrityReport {
  verified: boolean;
  totalEntries: number;
  brokenAt: number | null;
  expectedHash: string | null;
  actualHash: string | null;
  timestamp: string;
}

// ── Store ────────────────────────────────────────────────────

interface LedgerStore {
  engine: string;
  version: string;
  createdAt: string;
  lastUpdated: string;
  entries: AccessEntry[];
}

const STORE_DIR = path.join(process.cwd(), ".doc-engine");
const STORE_PATH = path.join(STORE_DIR, "sdc-access-ledger.json");

function loadStore(): LedgerStore {
  if (fs.existsSync(STORE_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    } catch {
      console.warn("[ACCESS-LEDGER] Corrupt ledger — creating new one");
    }
  }
  return {
    engine: "Document Intelligence Engine — SDC Access Ledger",
    version: "1.0.0",
    createdAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    entries: [],
  };
}

function saveStore(store: LedgerStore): void {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  store.lastUpdated = new Date().toISOString();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), "utf-8");
}

// ── Access Ledger ────────────────────────────────────────────

export class AccessLedger {
  private store: LedgerStore;

  constructor() {
    this.store = loadStore();
  }

  /**
   * Record a new access entry. Append-only — entries cannot be modified.
   */
  record(params: {
    documentId: string;
    intakeId?: string;
    tokenId?: string;
    action: AccessAction;
    actor: string;
    organization?: string;
    ipAddress?: string;
    deviceFingerprint?: string;
    userAgent?: string;
    geoLocation?: string;
    details: string;
    result: "granted" | "denied" | "info";
    denialReason?: string;
    documentHash?: string;
    watermarkId?: string;
    exportId?: string;
    metadata?: Record<string, string>;
  }): AccessEntry {
    const entryId = crypto.randomBytes(16).toString("hex");
    const sequence = this.store.entries.length + 1;
    const timestamp = new Date().toISOString();
    const previousHash = this.getLastChainHash();

    const partial = {
      entryId,
      sequence,
      timestamp,
      documentId: params.documentId,
      intakeId: params.intakeId,
      tokenId: params.tokenId,
      action: params.action,
      actor: params.actor,
      organization: params.organization,
      ipAddress: params.ipAddress,
      deviceFingerprint: params.deviceFingerprint,
      userAgent: params.userAgent,
      geoLocation: params.geoLocation,
      details: params.details,
      result: params.result,
      denialReason: params.denialReason,
      documentHash: params.documentHash,
      watermarkId: params.watermarkId,
      exportId: params.exportId,
      metadata: params.metadata || {},
    };

    const chainHash = this.computeChainHash(partial, previousHash);
    const entry: AccessEntry = { ...partial, chainHash };

    this.store.entries.push(entry);
    saveStore(this.store);

    return entry;
  }

  /**
   * Query the ledger with filters.
   */
  query(filters: AccessQuery): AccessEntry[] {
    let results = [...this.store.entries];

    if (filters.documentId) {
      results = results.filter((e) => e.documentId === filters.documentId);
    }
    if (filters.actor) {
      results = results.filter((e) => e.actor === filters.actor);
    }
    if (filters.action) {
      results = results.filter((e) => e.action === filters.action);
    }
    if (filters.result) {
      results = results.filter((e) => e.result === filters.result);
    }
    if (filters.tokenId) {
      results = results.filter((e) => e.tokenId === filters.tokenId);
    }
    if (filters.after) {
      results = results.filter((e) => e.timestamp >= filters.after!);
    }
    if (filters.before) {
      results = results.filter((e) => e.timestamp <= filters.before!);
    }
    if (filters.limit) {
      results = results.slice(-filters.limit);
    }

    return results;
  }

  /**
   * Get all access records for a document.
   */
  getByDocument(documentId: string): AccessEntry[] {
    return this.store.entries.filter((e) => e.documentId === documentId);
  }

  /**
   * Get all access records for a specific actor.
   */
  getByActor(actor: string): AccessEntry[] {
    return this.store.entries.filter((e) => e.actor === actor);
  }

  /**
   * Get denial records (security incidents).
   */
  getDenials(): AccessEntry[] {
    return this.store.entries.filter((e) => e.result === "denied");
  }

  /**
   * Get security-relevant events (screenshots, copy attempts, auth failures).
   */
  getSecurityEvents(): AccessEntry[] {
    const securityActions: AccessAction[] = [
      "screenshot-detected",
      "copied",
      "auth-failed",
      "otp-failed",
      "access-denied",
    ];
    return this.store.entries.filter((e) => securityActions.includes(e.action));
  }

  /**
   * Generate a forensic timeline for a document.
   */
  getTimeline(documentId: string): string[] {
    const entries = this.getByDocument(documentId);
    return entries.map(
      (e) =>
        `[${e.timestamp}] ${e.action.toUpperCase()} by ${e.actor}` +
        (e.ipAddress ? ` from ${e.ipAddress}` : "") +
        ` — ${e.details}` +
        (e.result === "denied" ? ` [DENIED: ${e.denialReason}]` : "")
    );
  }

  /**
   * Verify the integrity of the entire chain.
   */
  verifyIntegrity(): IntegrityReport {
    const timestamp = new Date().toISOString();
    if (this.store.entries.length === 0) {
      return {
        verified: true,
        totalEntries: 0,
        brokenAt: null,
        expectedHash: null,
        actualHash: null,
        timestamp,
      };
    }

    let previousHash = this.getGenesisHash();

    for (let i = 0; i < this.store.entries.length; i++) {
      const entry = this.store.entries[i];
      const expectedHash = this.computeChainHash(entry, previousHash);
      if (expectedHash !== entry.chainHash) {
        return {
          verified: false,
          totalEntries: this.store.entries.length,
          brokenAt: i + 1,
          expectedHash,
          actualHash: entry.chainHash,
          timestamp,
        };
      }
      previousHash = entry.chainHash;
    }

    return {
      verified: true,
      totalEntries: this.store.entries.length,
      brokenAt: null,
      expectedHash: null,
      actualHash: null,
      timestamp,
    };
  }

  /**
   * Get ledger statistics.
   */
  getStats(): LedgerStats {
    const docs = new Set<string>();
    const actors = new Set<string>();
    const actionCounts: Record<string, number> = {};
    let denials = 0;

    for (const e of this.store.entries) {
      docs.add(e.documentId);
      actors.add(e.actor);
      actionCounts[e.action] = (actionCounts[e.action] || 0) + 1;
      if (e.result === "denied") denials++;
    }

    const integrity = this.verifyIntegrity();

    return {
      totalEntries: this.store.entries.length,
      uniqueDocuments: docs.size,
      uniqueActors: actors.size,
      actionCounts,
      denialCount: denials,
      chainIntact: integrity.verified,
      firstEntry: this.store.entries[0]?.timestamp || "—",
      lastEntry: this.store.entries[this.store.entries.length - 1]?.timestamp || "—",
    };
  }

  /**
   * Export ledger as compliance report.
   */
  generateComplianceReport(documentId?: string): string {
    const entries = documentId
      ? this.getByDocument(documentId)
      : this.store.entries;

    const integrity = this.verifyIntegrity();
    const stats = this.getStats();

    const lines: string[] = [
      "═══════════════════════════════════════════════",
      "   SDC ACCESS LEDGER — COMPLIANCE REPORT",
      "═══════════════════════════════════════════════",
      "",
      `Report Generated: ${new Date().toISOString()}`,
      `Scope: ${documentId ? `Document ${documentId.substring(0, 16)}` : "All Documents"}`,
      "",
      "── Chain Integrity ──────────────────────────",
      `Status: ${integrity.verified ? "VERIFIED ✓" : "BROKEN ✗"}`,
      `Total Entries: ${integrity.totalEntries}`,
      ...(integrity.brokenAt
        ? [`Chain Broken at Entry: ${integrity.brokenAt}`]
        : []),
      "",
      "── Statistics ───────────────────────────────",
      `Total Access Events: ${entries.length}`,
      `Unique Documents: ${stats.uniqueDocuments}`,
      `Unique Actors: ${stats.uniqueActors}`,
      `Denials / Security Events: ${stats.denialCount}`,
      "",
      "── Action Breakdown ─────────────────────────",
      ...Object.entries(stats.actionCounts)
        .sort(([, a], [, b]) => b - a)
        .map(([action, count]) => `  ${action}: ${count}`),
      "",
      "── Security Events ──────────────────────────",
    ];

    const securityEvents = this.getSecurityEvents();
    if (securityEvents.length === 0) {
      lines.push("  No security events recorded.");
    } else {
      for (const e of securityEvents.slice(-20)) {
        lines.push(`  [${e.timestamp}] ${e.action} by ${e.actor} — ${e.details}`);
      }
    }

    lines.push("");
    lines.push("── Denial Log ───────────────────────────────");
    const denials = entries.filter((e) => e.result === "denied");
    if (denials.length === 0) {
      lines.push("  No denials recorded.");
    } else {
      for (const d of denials.slice(-20)) {
        lines.push(
          `  [${d.timestamp}] ${d.action} by ${d.actor}` +
          ` — DENIED: ${d.denialReason || "unspecified"}`
        );
      }
    }

    lines.push("");
    lines.push("── Full Timeline ────────────────────────────");
    for (const e of entries.slice(-50)) {
      const prefix = e.result === "denied" ? "✗" : e.result === "granted" ? "✓" : "·";
      lines.push(
        `  ${prefix} [${e.timestamp}] ${e.action} by ${e.actor}` +
        (e.ipAddress ? ` (${e.ipAddress})` : "") +
        ` — ${e.details}`
      );
    }

    lines.push("");
    lines.push("═══════════════════════════════════════════════");
    lines.push(`Chain Hash (last): ${this.store.entries[this.store.entries.length - 1]?.chainHash.substring(0, 32) || "—"}`);
    lines.push("═══════════════════════════════════════════════");

    return lines.join("\n");
  }

  // ── Private Methods ──────────────────────────────────────

  private getGenesisHash(): string {
    return crypto.createHash("sha256").update("sdc-access-ledger-genesis").digest("hex");
  }

  private getLastChainHash(): string {
    if (this.store.entries.length === 0) {
      return this.getGenesisHash();
    }
    return this.store.entries[this.store.entries.length - 1].chainHash;
  }

  private computeChainHash(
    entry: Omit<AccessEntry, "chainHash">,
    previousHash: string
  ): string {
    const payload = `${entry.entryId}:${entry.documentId}:${entry.action}:${entry.timestamp}:${previousHash}`;
    return crypto.createHash("sha256").update(payload).digest("hex");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _ledger: AccessLedger | null = null;

export function getAccessLedger(): AccessLedger {
  if (!_ledger) {
    _ledger = new AccessLedger();
  }
  return _ledger;
}
