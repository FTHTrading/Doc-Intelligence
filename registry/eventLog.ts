// ─────────────────────────────────────────────────────────────
// Document Event Log — Full lifecycle event tracking
// Every action on a document is recorded: ingest, parse,
// transform, export, sign, anchor, verify, access.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

/** All trackable document lifecycle actions */
export type DocumentAction =
  | "created"
  | "ingested"
  | "parsed"
  | "transformed"
  | "exported"
  | "fingerprinted"
  | "anchored"
  | "signed"
  | "verified"
  | "archived"
  | "accessed"
  | "modified"
  | "revoked"
  | "transferred"
  | "registry-added"
  | "sku-assigned"
  | "qr-generated"
  | "multisig-created"
  | "compared"
  | "error";

/** A single event in the document lifecycle */
export interface DocumentEvent {
  /** Unique event ID */
  eventId: string;
  /** Document ID this event belongs to */
  documentId: string;
  /** Document SKU (if assigned) */
  sku?: string;
  /** The action performed */
  action: DocumentAction;
  /** Who or what performed the action */
  actor: string;
  /** ISO timestamp */
  timestamp: string;
  /** Human-readable details */
  details: string;
  /** SHA-256 of the document state at this event (if applicable) */
  fingerprint?: string;
  /** IPFS CID (if applicable) */
  cid?: string;
  /** Chain-link hash — hash of this event + previous event hash */
  chainHash: string;
  /** Additional metadata */
  metadata: Record<string, string>;
}

/** Event log query filters */
export interface EventQuery {
  documentId?: string;
  action?: DocumentAction;
  actor?: string;
  after?: string;   // ISO timestamp
  before?: string;  // ISO timestamp
  limit?: number;
}

/** Event log statistics */
export interface EventLogStats {
  totalEvents: number;
  uniqueDocuments: number;
  actionCounts: Record<string, number>;
  actorCounts: Record<string, number>;
  firstEvent: string;
  lastEvent: string;
}

/** Persisted event log store */
interface EventLogStore {
  engine: string;
  version: string;
  createdAt: string;
  lastUpdated: string;
  events: DocumentEvent[];
}

const EVENT_LOG_FILE = "event-log.json";

export class DocumentEventLog {
  private store: EventLogStore;
  private logPath: string;

  constructor(logDir: string) {
    this.logPath = path.join(logDir, EVENT_LOG_FILE);
    this.store = this.load();
  }

  /** Load event log from disk */
  private load(): EventLogStore {
    if (fs.existsSync(this.logPath)) {
      try {
        const raw = fs.readFileSync(this.logPath, "utf-8");
        return JSON.parse(raw) as EventLogStore;
      } catch {
        console.warn("[EVENT-LOG] Corrupt log file — creating new one");
      }
    }
    return {
      engine: "Document Intelligence Engine",
      version: "1.0.0",
      createdAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      events: [],
    };
  }

  /** Persist to disk */
  private save(): void {
    const dir = path.dirname(this.logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    this.store.lastUpdated = new Date().toISOString();
    fs.writeFileSync(this.logPath, JSON.stringify(this.store, null, 2), "utf-8");
  }

  /** Generate a unique event ID */
  private generateEventId(): string {
    return crypto.randomBytes(12).toString("hex");
  }

  /** Compute chain hash linking to previous event */
  private computeChainHash(event: Omit<DocumentEvent, "chainHash">, previousHash: string): string {
    const payload = `${event.eventId}:${event.documentId}:${event.action}:${event.timestamp}:${previousHash}`;
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  /** Get the last chain hash in the log */
  private getLastChainHash(): string {
    if (this.store.events.length === 0) {
      return crypto.createHash("sha256").update("genesis").digest("hex");
    }
    return this.store.events[this.store.events.length - 1].chainHash;
  }

  /** Log a new event */
  log(params: {
    documentId: string;
    sku?: string;
    action: DocumentAction;
    actor: string;
    details: string;
    fingerprint?: string;
    cid?: string;
    metadata?: Record<string, string>;
  }): DocumentEvent {
    const eventId = this.generateEventId();
    const timestamp = new Date().toISOString();
    const previousHash = this.getLastChainHash();

    const partial = {
      eventId,
      documentId: params.documentId,
      sku: params.sku,
      action: params.action,
      actor: params.actor,
      timestamp,
      details: params.details,
      fingerprint: params.fingerprint,
      cid: params.cid,
      metadata: params.metadata || {},
    };

    const chainHash = this.computeChainHash(partial, previousHash);
    const event: DocumentEvent = { ...partial, chainHash };

    this.store.events.push(event);
    this.save();

    return event;
  }

  /** Get all events for a document */
  getDocumentHistory(documentId: string): DocumentEvent[] {
    return this.store.events
      .filter((e) => e.documentId === documentId)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }

  /** Query events with filters */
  query(filters: EventQuery): DocumentEvent[] {
    let results = [...this.store.events];

    if (filters.documentId) {
      results = results.filter((e) => e.documentId === filters.documentId);
    }
    if (filters.action) {
      results = results.filter((e) => e.action === filters.action);
    }
    if (filters.actor) {
      results = results.filter(
        (e) => e.actor.toLowerCase() === filters.actor!.toLowerCase()
      );
    }
    if (filters.after) {
      const after = new Date(filters.after).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() > after);
    }
    if (filters.before) {
      const before = new Date(filters.before).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() < before);
    }

    // Sort chronologically
    results.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    if (filters.limit) {
      results = results.slice(-filters.limit);
    }

    return results;
  }

  /** Verify the chain hash integrity of the entire log */
  verifyChain(): { valid: boolean; brokenAt?: number; details: string } {
    const events = this.store.events;
    if (events.length === 0) {
      return { valid: true, details: "Empty log — no events to verify." };
    }

    let previousHash = crypto.createHash("sha256").update("genesis").digest("hex");

    for (let i = 0; i < events.length; i++) {
      const event = events[i];
      const { chainHash, ...rest } = event;
      const expected = this.computeChainHash(rest, previousHash);

      if (expected !== chainHash) {
        return {
          valid: false,
          brokenAt: i,
          details: `Chain integrity broken at event ${i} (${event.eventId}). Expected ${expected.substring(0, 16)}..., found ${chainHash.substring(0, 16)}...`,
        };
      }
      previousHash = chainHash;
    }

    return {
      valid: true,
      details: `Chain verified — ${events.length} events, all hashes valid.`,
    };
  }

  /** Get log statistics */
  getStats(): EventLogStats {
    const events = this.store.events;
    if (events.length === 0) {
      return {
        totalEvents: 0,
        uniqueDocuments: 0,
        actionCounts: {},
        actorCounts: {},
        firstEvent: "",
        lastEvent: "",
      };
    }

    const uniqueDocs = new Set(events.map((e) => e.documentId));
    const actionCounts: Record<string, number> = {};
    const actorCounts: Record<string, number> = {};

    for (const e of events) {
      actionCounts[e.action] = (actionCounts[e.action] || 0) + 1;
      actorCounts[e.actor] = (actorCounts[e.actor] || 0) + 1;
    }

    const sorted = [...events].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    return {
      totalEvents: events.length,
      uniqueDocuments: uniqueDocs.size,
      actionCounts,
      actorCounts,
      firstEvent: sorted[0].timestamp,
      lastEvent: sorted[sorted.length - 1].timestamp,
    };
  }

  /** Export document timeline as a formatted report */
  exportTimeline(documentId: string): string {
    const events = this.getDocumentHistory(documentId);
    if (events.length === 0) return "No events found for this document.";

    const lines: string[] = [
      "═══════════════════════════════════════════════════════",
      `  DOCUMENT EVENT TIMELINE`,
      `  Document: ${documentId}`,
      `  Events: ${events.length}`,
      "═══════════════════════════════════════════════════════",
      "",
    ];

    for (const e of events) {
      const ts = new Date(e.timestamp).toLocaleString();
      lines.push(`  [${ts}] ${e.action.toUpperCase()}`);
      lines.push(`    Actor: ${e.actor}`);
      lines.push(`    ${e.details}`);
      if (e.cid) lines.push(`    CID: ${e.cid}`);
      if (e.fingerprint) lines.push(`    Hash: ${e.fingerprint.substring(0, 16)}...`);
      lines.push(`    Chain: ${e.chainHash.substring(0, 16)}...`);
      lines.push("");
    }

    return lines.join("\n");
  }

  /** Get total event count */
  get length(): number {
    return this.store.events.length;
  }
}

/** Singleton event log instance */
let _eventLog: DocumentEventLog | null = null;

export function getEventLog(logDir?: string): DocumentEventLog {
  if (!_eventLog) {
    const dir = logDir || path.join(process.cwd(), ".doc-engine");
    _eventLog = new DocumentEventLog(dir);
  }
  return _eventLog;
}
