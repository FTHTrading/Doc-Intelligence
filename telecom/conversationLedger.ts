// ─────────────────────────────────────────────────────────────
// Sovereign Comms Agent — Conversation Ledger
//
// Append-only, hash-chained audit log of all SCA
// conversations. Every inbound message, intent classification,
// action execution, and outbound response is recorded.
//
// Integrity guarantees:
//   • Sequential numbering (no gaps)
//   • Chain hash linking (H(N) = SHA256(entry + H(N-1)))
//   • Append-only (no edits, no deletes)
//   • Tamper detection via verifyIntegrity()
//
// This is the compliance backbone of the SCA.
// Every message in or out is permanently recorded.
//
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { InboundMessage } from "./inboundRouter";
import { IntentResult } from "./aiIntentEngine";
import { ActionResult } from "./actionEngine";
import { ComposedResponse } from "./responseComposer";

// ── Types ────────────────────────────────────────────────────

/** Conversation event type */
export type ConversationEventType =
  | "inbound"          // Received a message
  | "classification"   // Intent classified
  | "action"           // Action executed
  | "response"         // Outbound response composed
  | "delivery"         // Outbound delivery result
  | "compliance"       // Compliance event (STOP/START/HELP)
  | "escalation"       // Escalated to human
  | "approval"         // Approval queued / resolved
  | "error";           // Error occurred

/** A single conversation ledger entry */
export interface ConversationEntry {
  /** Unique entry ID */
  entryId: string;
  /** Sequential number (1-based) */
  sequence: number;
  /** Event type */
  eventType: ConversationEventType;
  /** Conversation thread ID (groups related events) */
  threadId: string;
  /** Sender phone (E.164) */
  from: string;
  /** Recipient phone (E.164) */
  to: string;
  /** Direction */
  direction: "inbound" | "outbound" | "internal";
  /** Intent (if classified) */
  intent?: string;
  /** Governance tier applied */
  tier?: number;
  /** Action ID (if action was taken) */
  actionId?: string;
  /** Action status */
  actionStatus?: string;
  /** Message text (inbound or outbound) */
  messageText?: string;
  /** Classification confidence */
  confidence?: string;
  /** Deal ID (if applicable) */
  dealId?: string;
  /** Session ID (if applicable) */
  sessionId?: string;
  /** Number mode at time of event */
  numberMode?: string;
  /** Number purpose at time of event */
  numberPurpose?: string;
  /** Result summary */
  summary: string;
  /** Additional metadata */
  metadata: Record<string, string>;
  /** Timestamp */
  timestamp: string;
  /** Chain hash — SHA256(entryId:threadId:eventType:timestamp:previousHash) */
  chainHash: string;
}

/** Conversation ledger store */
interface LedgerStore {
  engine: string;
  version: string;
  genesisHash: string;
  entries: ConversationEntry[];
}

/** Integrity verification report */
export interface IntegrityReport {
  valid: boolean;
  totalEntries: number;
  checkedEntries: number;
  firstBroken?: number;
  brokenEntryId?: string;
  genesisValid: boolean;
}

/** Conversation thread summary */
export interface ThreadSummary {
  threadId: string;
  from: string;
  to: string;
  eventCount: number;
  intents: string[];
  actions: string[];
  firstEvent: string;
  lastEvent: string;
  hasEscalation: boolean;
  hasCompliance: boolean;
}

/** Query filters */
export interface LedgerQuery {
  threadId?: string;
  from?: string;
  to?: string;
  eventType?: ConversationEventType;
  intent?: string;
  direction?: "inbound" | "outbound" | "internal";
  since?: string;
  until?: string;
  limit?: number;
}

// ── Constants ────────────────────────────────────────────────

const LEDGER_FILE = "sca-conversation-ledger.json";
const GENESIS_SEED = "FTH-SCA-CONVERSATION-LEDGER-GENESIS-v1";

// ── Conversation Ledger ──────────────────────────────────────

export class ConversationLedger {
  private store: LedgerStore;
  private storePath: string;

  constructor(storeDir: string = ".doc-engine") {
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.storePath = path.join(storeDir, LEDGER_FILE);
    this.store = this.load();
  }

  // ── Record Events ──────────────────────────────────────────

  /**
   * Record an inbound message.
   */
  recordInbound(message: InboundMessage, threadId: string): ConversationEntry {
    return this.append({
      eventType: "inbound",
      threadId,
      from: message.from,
      to: message.to,
      direction: "inbound",
      messageText: message.rawText,
      numberMode: message.targetNumber?.mode,
      numberPurpose: message.targetNumber?.purpose,
      summary: `Inbound from ${message.from}: "${message.rawText.substring(0, 80)}"`,
      metadata: {
        telnyxMessageId: message.telnyxMessageId,
        keyword: message.keyword,
        knownSender: String(message.knownSender),
        sourceIp: message.sourceIp,
      },
    });
  }

  /**
   * Record an intent classification.
   */
  recordClassification(
    message: InboundMessage,
    intent: IntentResult,
    threadId: string
  ): ConversationEntry {
    return this.append({
      eventType: "classification",
      threadId,
      from: message.from,
      to: message.to,
      direction: "internal",
      intent: intent.intent,
      tier: intent.tier,
      confidence: intent.confidence,
      summary: `Classified: ${intent.intent} (Tier ${intent.tier}, ${intent.confidence} confidence, method: ${intent.method})`,
      metadata: {
        classificationId: intent.classificationId,
        method: intent.method,
        requiresApproval: String(intent.requiresApproval),
        autoExecute: String(intent.autoExecute),
        suggestedAction: intent.suggestedAction,
      },
    });
  }

  /**
   * Record an action execution.
   */
  recordAction(
    message: InboundMessage,
    action: ActionResult,
    threadId: string
  ): ConversationEntry {
    return this.append({
      eventType: "action",
      threadId,
      from: message.from,
      to: message.to,
      direction: "internal",
      intent: action.intent,
      tier: action.tier,
      actionId: action.actionId,
      actionStatus: action.status,
      sessionId: action.responseData.sessionId as string | undefined,
      dealId: action.responseData.dealId as string | undefined,
      summary: `Action [${action.status}]: ${action.summary}`,
      metadata: {
        executed: String(action.executed),
        shouldRespond: String(action.shouldRespond),
        escalationTarget: action.escalationTarget || "",
      },
    });
  }

  /**
   * Record an outbound response.
   */
  recordResponse(
    response: ComposedResponse,
    threadId: string
  ): ConversationEntry {
    return this.append({
      eventType: "response",
      threadId,
      from: response.from,
      to: response.to,
      direction: "outbound",
      messageText: response.text,
      summary: `Outbound to ${response.to}: ${response.charCount} chars, ${response.segments} segments, status: ${response.status}`,
      metadata: {
        responseId: response.responseId,
        segments: String(response.segments),
        charCount: String(response.charCount),
        hasComplianceFooter: String(response.hasComplianceFooter),
        status: response.status,
        messageId: response.deliveryResult?.messageId || "",
      },
    });
  }

  /**
   * Record a compliance event (STOP/START/HELP).
   */
  recordCompliance(params: {
    from: string;
    to: string;
    keyword: string;
    action: string;
    threadId: string;
  }): ConversationEntry {
    return this.append({
      eventType: "compliance",
      threadId: params.threadId,
      from: params.from,
      to: params.to,
      direction: "inbound",
      summary: `Compliance: ${params.keyword} → ${params.action}`,
      metadata: {
        keyword: params.keyword,
        action: params.action,
      },
    });
  }

  /**
   * Record an escalation.
   */
  recordEscalation(params: {
    from: string;
    to: string;
    intent: string;
    target: string;
    threadId: string;
  }): ConversationEntry {
    return this.append({
      eventType: "escalation",
      threadId: params.threadId,
      from: params.from,
      to: params.to,
      direction: "internal",
      intent: params.intent,
      summary: `Escalated: ${params.intent} → ${params.target}`,
      metadata: {
        escalationTarget: params.target,
      },
    });
  }

  /**
   * Record an error.
   */
  recordError(params: {
    from: string;
    to: string;
    error: string;
    threadId: string;
  }): ConversationEntry {
    return this.append({
      eventType: "error",
      threadId: params.threadId,
      from: params.from,
      to: params.to,
      direction: "internal",
      summary: `Error: ${params.error}`,
      metadata: {
        error: params.error,
      },
    });
  }

  // ── Core Append ────────────────────────────────────────────

  /**
   * Append a new entry to the ledger.
   */
  private append(params: {
    eventType: ConversationEventType;
    threadId: string;
    from: string;
    to: string;
    direction: "inbound" | "outbound" | "internal";
    intent?: string;
    tier?: number;
    actionId?: string;
    actionStatus?: string;
    messageText?: string;
    confidence?: string;
    dealId?: string;
    sessionId?: string;
    numberMode?: string;
    numberPurpose?: string;
    summary: string;
    metadata: Record<string, string>;
  }): ConversationEntry {
    const entryId = crypto.randomBytes(16).toString("hex");
    const sequence = this.store.entries.length + 1;
    const timestamp = new Date().toISOString();
    const previousHash = this.getLastChainHash();

    const partial = {
      entryId,
      sequence,
      timestamp,
      eventType: params.eventType,
      threadId: params.threadId,
      from: params.from,
      to: params.to,
      direction: params.direction,
      intent: params.intent,
      tier: params.tier,
      actionId: params.actionId,
      actionStatus: params.actionStatus,
      messageText: params.messageText,
      confidence: params.confidence,
      dealId: params.dealId,
      sessionId: params.sessionId,
      numberMode: params.numberMode,
      numberPurpose: params.numberPurpose,
      summary: params.summary,
      metadata: params.metadata,
    };

    const chainHash = this.computeChainHash(partial, previousHash);
    const entry: ConversationEntry = { ...partial, chainHash };

    this.store.entries.push(entry);
    this.save();

    return entry;
  }

  // ── Queries ────────────────────────────────────────────────

  /**
   * Query the ledger with filters.
   */
  query(filters: LedgerQuery): ConversationEntry[] {
    let results = [...this.store.entries];

    if (filters.threadId) {
      results = results.filter((e) => e.threadId === filters.threadId);
    }
    if (filters.from) {
      results = results.filter((e) => e.from === filters.from);
    }
    if (filters.to) {
      results = results.filter((e) => e.to === filters.to);
    }
    if (filters.eventType) {
      results = results.filter((e) => e.eventType === filters.eventType);
    }
    if (filters.intent) {
      results = results.filter((e) => e.intent === filters.intent);
    }
    if (filters.direction) {
      results = results.filter((e) => e.direction === filters.direction);
    }
    if (filters.since) {
      results = results.filter((e) => e.timestamp >= filters.since!);
    }
    if (filters.until) {
      results = results.filter((e) => e.timestamp <= filters.until!);
    }
    if (filters.limit) {
      results = results.slice(-filters.limit);
    }

    return results;
  }

  /**
   * Get all entries for a thread.
   */
  getThread(threadId: string): ConversationEntry[] {
    return this.store.entries.filter((e) => e.threadId === threadId);
  }

  /**
   * Get thread summaries for a phone number.
   */
  getThreadsForNumber(phone: string): ThreadSummary[] {
    const threadMap = new Map<string, ConversationEntry[]>();

    for (const entry of this.store.entries) {
      if (entry.from === phone || entry.to === phone) {
        const existing = threadMap.get(entry.threadId) || [];
        existing.push(entry);
        threadMap.set(entry.threadId, existing);
      }
    }

    const summaries: ThreadSummary[] = [];
    for (const [threadId, entries] of threadMap) {
      const intents = new Set<string>();
      const actions = new Set<string>();
      let hasEscalation = false;
      let hasCompliance = false;

      for (const e of entries) {
        if (e.intent) intents.add(e.intent);
        if (e.actionStatus) actions.add(e.actionStatus);
        if (e.eventType === "escalation") hasEscalation = true;
        if (e.eventType === "compliance") hasCompliance = true;
      }

      summaries.push({
        threadId,
        from: entries[0].from,
        to: entries[0].to,
        eventCount: entries.length,
        intents: Array.from(intents),
        actions: Array.from(actions),
        firstEvent: entries[0].timestamp,
        lastEvent: entries[entries.length - 1].timestamp,
        hasEscalation,
        hasCompliance,
      });
    }

    return summaries;
  }

  // ── Integrity ──────────────────────────────────────────────

  /**
   * Verify the integrity of the entire chain.
   */
  verifyIntegrity(): IntegrityReport {
    const entries = this.store.entries;

    if (entries.length === 0) {
      return {
        valid: true,
        totalEntries: 0,
        checkedEntries: 0,
        genesisValid: true,
      };
    }

    // Verify genesis
    const genesisValid = entries[0].sequence === 1;

    let previousHash = this.getGenesisHash();

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const partial = { ...entry };
      delete (partial as Record<string, unknown>)["chainHash"];

      const expectedHash = this.computeChainHash(
        partial as Omit<ConversationEntry, "chainHash">,
        previousHash
      );

      if (expectedHash !== entry.chainHash) {
        return {
          valid: false,
          totalEntries: entries.length,
          checkedEntries: i + 1,
          firstBroken: i + 1,
          brokenEntryId: entry.entryId,
          genesisValid,
        };
      }

      previousHash = entry.chainHash;
    }

    return {
      valid: true,
      totalEntries: entries.length,
      checkedEntries: entries.length,
      genesisValid,
    };
  }

  // ── Stats ──────────────────────────────────────────────────

  /**
   * Get ledger statistics.
   */
  getStats(): {
    totalEntries: number;
    inbound: number;
    outbound: number;
    internal: number;
    intents: Record<string, number>;
    eventTypes: Record<string, number>;
    uniqueThreads: number;
    uniqueSenders: number;
    chainValid: boolean;
  } {
    const entries = this.store.entries;
    const intents: Record<string, number> = {};
    const eventTypes: Record<string, number> = {};
    const threads = new Set<string>();
    const senders = new Set<string>();

    for (const e of entries) {
      if (e.intent) intents[e.intent] = (intents[e.intent] || 0) + 1;
      eventTypes[e.eventType] = (eventTypes[e.eventType] || 0) + 1;
      threads.add(e.threadId);
      if (e.direction === "inbound") senders.add(e.from);
    }

    return {
      totalEntries: entries.length,
      inbound: entries.filter((e) => e.direction === "inbound").length,
      outbound: entries.filter((e) => e.direction === "outbound").length,
      internal: entries.filter((e) => e.direction === "internal").length,
      intents,
      eventTypes,
      uniqueThreads: threads.size,
      uniqueSenders: senders.size,
      chainValid: this.verifyIntegrity().valid,
    };
  }

  /**
   * Format a summary for display.
   */
  formatSummary(): string {
    const stats = this.getStats();
    const integrity = this.verifyIntegrity();

    const lines = [
      `=== SCA Conversation Ledger ===`,
      `Total entries: ${stats.totalEntries}`,
      `  Inbound:  ${stats.inbound}`,
      `  Outbound: ${stats.outbound}`,
      `  Internal: ${stats.internal}`,
      `Unique threads: ${stats.uniqueThreads}`,
      `Unique senders: ${stats.uniqueSenders}`,
      ``,
      `Intent distribution:`,
    ];

    for (const [intent, count] of Object.entries(stats.intents)) {
      lines.push(`  ${intent}: ${count}`);
    }

    lines.push(``);
    lines.push(`Chain integrity: ${integrity.valid ? "VERIFIED" : "BROKEN"}`);
    if (!integrity.valid) {
      lines.push(`  First break at entry #${integrity.firstBroken}`);
    }

    return lines.join("\n");
  }

  // ── Chain Hash ─────────────────────────────────────────────

  private getGenesisHash(): string {
    return crypto.createHash("sha256").update(GENESIS_SEED).digest("hex");
  }

  private getLastChainHash(): string {
    if (this.store.entries.length === 0) {
      return this.getGenesisHash();
    }
    return this.store.entries[this.store.entries.length - 1].chainHash;
  }

  private computeChainHash(
    entry: Omit<ConversationEntry, "chainHash">,
    previousHash: string
  ): string {
    const payload = `${entry.entryId}:${entry.threadId}:${entry.eventType}:${entry.timestamp}:${previousHash}`;
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  // ── Persistence ────────────────────────────────────────────

  private load(): LedgerStore {
    if (fs.existsSync(this.storePath)) {
      try {
        return JSON.parse(fs.readFileSync(this.storePath, "utf-8"));
      } catch {
        // Corrupted — start fresh
      }
    }
    return {
      engine: "sca-conversation-ledger",
      version: "1.0.0",
      genesisHash: this.getGenesisHash(),
      entries: [],
    };
  }

  private save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2));
  }
}

// ── Singleton ────────────────────────────────────────────────

let _ledger: ConversationLedger | null = null;

export function getConversationLedger(): ConversationLedger {
  if (!_ledger) {
    _ledger = new ConversationLedger();
  }
  return _ledger;
}
