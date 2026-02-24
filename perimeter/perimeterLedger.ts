// ─────────────────────────────────────────────────────────────
// Cloudflare Perimeter — Security Event Ledger
//
// Append-only, SHA-256 chain-hashed audit ledger for all
// perimeter security events:
//   • Webhook validations (pass/fail)
//   • Rate limit decisions (allow/block)
//   • Tunnel state changes (start/stop/reconnect)
//   • WAF events (simulated local tracking)
//   • IP block/unblock actions
//   • Configuration changes
//
// Follows the chain-hash pattern from VaultLedger, EventLog,
// AccessLedger, and ConversationLedger — forensic-grade,
// tamper-evident security event recording.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// Re-import the ValidationResult type from webhookValidator
// to avoid circular deps — we accept a compatible shape
export interface ValidationResultShape {
  allowed: boolean;
  reason: string;
  passed: string[];
  failed: string[];
  riskScore: number;
  sourceIp: string;
  validationId: string;
  timestamp: string;
}

// ── Types ────────────────────────────────────────────────────

export type PerimeterEventType =
  | "validation-pass"
  | "validation-fail"
  | "rate-limit-allow"
  | "rate-limit-block"
  | "tunnel-started"
  | "tunnel-stopped"
  | "tunnel-reconnected"
  | "tunnel-error"
  | "ip-blocked"
  | "ip-unblocked"
  | "waf-triggered"
  | "config-changed"
  | "health-check"
  | "dns-updated"
  | "certificate-renewed"
  | "geo-blocked"
  | "bot-detected"
  | "nonce-replay"
  | "signature-invalid"
  | "perimeter-startup"
  | "perimeter-shutdown";

export type PerimeterSeverity = "info" | "warn" | "alert" | "critical";

export interface PerimeterEntry {
  /** Unique entry ID */
  entryId: string;
  /** Sequence number (1-based, monotonic) */
  sequence: number;
  /** Event type */
  eventType: PerimeterEventType;
  /** Severity level */
  severity: PerimeterSeverity;
  /** ISO timestamp */
  timestamp: string;
  /** Source IP (if applicable) */
  sourceIp?: string;
  /** Target service */
  targetService?: string;
  /** Human-readable description */
  description: string;
  /** Validation ID (if this is a validation event) */
  validationId?: string;
  /** Rate limit bucket key (if rate limit event) */
  bucketKey?: string;
  /** Tunnel ID (if tunnel event) */
  tunnelId?: string;
  /** WAF rule ID (if WAF event) */
  wafRuleId?: string;
  /** Risk score (0–100, from validation) */
  riskScore?: number;
  /** Checks passed (if validation event) */
  checksPassed?: string[];
  /** Checks failed (if validation event) */
  checksFailed?: string[];
  /** Additional metadata */
  metadata: Record<string, string>;
  /** Chain hash — SHA-256(sequence + entryId + eventType + timestamp + previousHash) */
  chainHash: string;
}

export interface PerimeterLedgerStore {
  version: string;
  createdAt: string;
  entries: PerimeterEntry[];
}

export interface PerimeterLedgerStats {
  totalEntries: number;
  eventCounts: Record<string, number>;
  severityCounts: Record<string, number>;
  validationPassCount: number;
  validationFailCount: number;
  rateLimitBlockCount: number;
  uniqueIPs: number;
  chainIntact: boolean;
  firstEntry: string;
  lastEntry: string;
}

export interface PerimeterQuery {
  eventType?: PerimeterEventType;
  severity?: PerimeterSeverity;
  sourceIp?: string;
  after?: string;
  before?: string;
  limit?: number;
}

// ── Ledger ───────────────────────────────────────────────────

const DATA_DIR = path.join(process.cwd(), ".doc-engine");
const LEDGER_PATH = path.join(DATA_DIR, "perimeter-ledger.json");
const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

export class PerimeterLedger {
  private store: PerimeterLedgerStore;

  constructor() {
    this.store = this.load();
  }

  // ── Record Methods ─────────────────────────────────────────

  /**
   * Record a webhook validation result.
   */
  recordValidation(result: ValidationResultShape): PerimeterEntry {
    const eventType: PerimeterEventType = result.allowed ? "validation-pass" : "validation-fail";
    const severity: PerimeterSeverity = result.allowed
      ? "info"
      : result.riskScore >= 80
        ? "critical"
        : result.riskScore >= 50
          ? "alert"
          : "warn";

    return this.append({
      eventType,
      severity,
      sourceIp: result.sourceIp,
      description: result.reason,
      validationId: result.validationId,
      riskScore: result.riskScore,
      checksPassed: result.passed,
      checksFailed: result.failed,
      metadata: {},
    });
  }

  /**
   * Record a rate limit decision.
   */
  recordRateLimit(decision: {
    allowed: boolean;
    bucketKey: string;
    bucketType: string;
    currentCount: number;
    limit: number;
    sourceIp?: string;
    endpoint?: string;
  }): PerimeterEntry {
    return this.append({
      eventType: decision.allowed ? "rate-limit-allow" : "rate-limit-block",
      severity: decision.allowed ? "info" : "warn",
      sourceIp: decision.sourceIp,
      bucketKey: decision.bucketKey,
      description: decision.allowed
        ? `Rate limit OK: ${decision.bucketKey} (${decision.currentCount}/${decision.limit})`
        : `Rate limit EXCEEDED: ${decision.bucketKey} (${decision.currentCount}/${decision.limit})`,
      metadata: {
        bucketType: decision.bucketType,
        currentCount: String(decision.currentCount),
        limit: String(decision.limit),
        ...(decision.endpoint ? { endpoint: decision.endpoint } : {}),
      },
    });
  }

  /**
   * Record a tunnel state change.
   */
  recordTunnelEvent(event: {
    eventType: "tunnel-started" | "tunnel-stopped" | "tunnel-reconnected" | "tunnel-error";
    tunnelId?: string;
    description: string;
    metadata?: Record<string, string>;
  }): PerimeterEntry {
    const severity: PerimeterSeverity =
      event.eventType === "tunnel-error" ? "alert" :
      event.eventType === "tunnel-stopped" ? "warn" : "info";

    return this.append({
      eventType: event.eventType,
      severity,
      tunnelId: event.tunnelId,
      description: event.description,
      metadata: event.metadata || {},
    });
  }

  /**
   * Record an IP block/unblock action.
   */
  recordIPAction(action: "ip-blocked" | "ip-unblocked", ip: string, reason: string): PerimeterEntry {
    return this.append({
      eventType: action,
      severity: action === "ip-blocked" ? "warn" : "info",
      sourceIp: ip,
      description: reason,
      metadata: {},
    });
  }

  /**
   * Record a WAF rule trigger.
   */
  recordWAFEvent(ruleId: string, sourceIp: string, description: string): PerimeterEntry {
    return this.append({
      eventType: "waf-triggered",
      severity: "alert",
      sourceIp,
      wafRuleId: ruleId,
      description,
      metadata: { ruleId },
    });
  }

  /**
   * Record a configuration change.
   */
  recordConfigChange(description: string, metadata?: Record<string, string>): PerimeterEntry {
    return this.append({
      eventType: "config-changed",
      severity: "info",
      description,
      metadata: metadata || {},
    });
  }

  /**
   * Record a geo-block event.
   */
  recordGeoBlock(sourceIp: string, country: string): PerimeterEntry {
    return this.append({
      eventType: "geo-blocked",
      severity: "warn",
      sourceIp,
      description: `Request from blocked country: ${country}`,
      metadata: { country },
    });
  }

  /**
   * Record a nonce replay attempt.
   */
  recordNonceReplay(sourceIp: string, nonce: string): PerimeterEntry {
    return this.append({
      eventType: "nonce-replay",
      severity: "alert",
      sourceIp,
      description: `Nonce replay attempt: ${nonce.substring(0, 16)}...`,
      metadata: { nonce },
    });
  }

  /**
   * Generic append for any event type.
   */
  recordEvent(eventType: PerimeterEventType, severity: PerimeterSeverity, description: string, metadata?: Record<string, string>): PerimeterEntry {
    return this.append({
      eventType,
      severity,
      description,
      metadata: metadata || {},
    });
  }

  // ── Core Append ────────────────────────────────────────────

  private append(partial: Omit<PerimeterEntry, "entryId" | "sequence" | "timestamp" | "chainHash">): PerimeterEntry {
    const sequence = this.store.entries.length + 1;
    const entryId = `PRM-${sequence.toString().padStart(6, "0")}-${crypto.randomBytes(4).toString("hex")}`;
    const timestamp = new Date().toISOString();
    const previousHash = this.getLastChainHash();

    const entryForHash = { ...partial, entryId, sequence, timestamp };
    const chainHash = this.computeChainHash(entryForHash, previousHash);

    const entry: PerimeterEntry = {
      ...partial,
      entryId,
      sequence,
      timestamp,
      chainHash,
    };

    this.store.entries.push(entry);
    this.persist();
    return entry;
  }

  // ── Query ──────────────────────────────────────────────────

  /**
   * Query ledger entries with filters.
   */
  query(q: PerimeterQuery): PerimeterEntry[] {
    let results = [...this.store.entries];

    if (q.eventType) results = results.filter((e) => e.eventType === q.eventType);
    if (q.severity) results = results.filter((e) => e.severity === q.severity);
    if (q.sourceIp) results = results.filter((e) => e.sourceIp === q.sourceIp);
    if (q.after) results = results.filter((e) => e.timestamp >= q.after!);
    if (q.before) results = results.filter((e) => e.timestamp <= q.before!);

    if (q.limit && q.limit > 0) {
      results = results.slice(-q.limit);
    }

    return results;
  }

  /**
   * Get recent events (last N).
   */
  getRecent(count: number = 20): PerimeterEntry[] {
    return this.store.entries.slice(-count);
  }

  /**
   * Get all entries.
   */
  getAll(): PerimeterEntry[] {
    return [...this.store.entries];
  }

  /**
   * Get count.
   */
  getCount(): number {
    return this.store.entries.length;
  }

  // ── Chain Integrity ────────────────────────────────────────

  /**
   * Verify the full hash chain integrity.
   */
  verifyChainIntegrity(): { intact: boolean; brokenAt?: number; details: string } {
    if (this.store.entries.length === 0) {
      return { intact: true, details: "Ledger is empty — no chain to verify." };
    }

    let previousHash = GENESIS_HASH;

    for (let i = 0; i < this.store.entries.length; i++) {
      const entry = this.store.entries[i];
      const { chainHash, ...rest } = entry;
      const expectedHash = this.computeChainHash(rest, previousHash);

      if (expectedHash !== entry.chainHash) {
        return {
          intact: false,
          brokenAt: i + 1,
          details: `Chain broken at entry ${i + 1} (${entry.entryId}). Expected ${expectedHash.substring(0, 16)}..., got ${entry.chainHash.substring(0, 16)}...`,
        };
      }

      previousHash = entry.chainHash;
    }

    return {
      intact: true,
      details: `Hash chain intact — ${this.store.entries.length} entries verified.`,
    };
  }

  // ── Statistics ─────────────────────────────────────────────

  /**
   * Get comprehensive ledger statistics.
   */
  getStats(): PerimeterLedgerStats {
    const eventCounts: Record<string, number> = {};
    const severityCounts: Record<string, number> = {};
    const uniqueIPs = new Set<string>();
    let validationPassCount = 0;
    let validationFailCount = 0;
    let rateLimitBlockCount = 0;

    for (const entry of this.store.entries) {
      eventCounts[entry.eventType] = (eventCounts[entry.eventType] || 0) + 1;
      severityCounts[entry.severity] = (severityCounts[entry.severity] || 0) + 1;

      if (entry.sourceIp) uniqueIPs.add(entry.sourceIp);
      if (entry.eventType === "validation-pass") validationPassCount++;
      if (entry.eventType === "validation-fail") validationFailCount++;
      if (entry.eventType === "rate-limit-block") rateLimitBlockCount++;
    }

    const chain = this.verifyChainIntegrity();

    return {
      totalEntries: this.store.entries.length,
      eventCounts,
      severityCounts,
      validationPassCount,
      validationFailCount,
      rateLimitBlockCount,
      uniqueIPs: uniqueIPs.size,
      chainIntact: chain.intact,
      firstEntry: this.store.entries.length > 0 ? this.store.entries[0].timestamp : "—",
      lastEntry: this.store.entries.length > 0 ? this.store.entries[this.store.entries.length - 1].timestamp : "—",
    };
  }

  // ── Display ────────────────────────────────────────────────

  /**
   * Format ledger status for CLI display.
   */
  formatStatus(): string {
    const stats = this.getStats();
    const chain = this.verifyChainIntegrity();

    const lines: string[] = [
      `  Perimeter Security Ledger`,
      `  ──────────────────────────────────────────────`,
      `  Total Events: ${stats.totalEntries}`,
      `  Chain Integrity: ${chain.intact ? "✓ INTACT" : "✗ BROKEN — " + chain.details}`,
      `  Validation Pass: ${stats.validationPassCount}`,
      `  Validation Fail: ${stats.validationFailCount}`,
      `  Rate Limit Blocks: ${stats.rateLimitBlockCount}`,
      `  Unique IPs: ${stats.uniqueIPs}`,
      `  First Event: ${stats.firstEntry}`,
      `  Last Event: ${stats.lastEntry}`,
    ];

    if (Object.keys(stats.severityCounts).length > 0) {
      lines.push(``);
      lines.push(`  By Severity:`);
      for (const [sev, count] of Object.entries(stats.severityCounts)) {
        const icon = sev === "critical" ? "⊘" : sev === "alert" ? "⚠" : sev === "warn" ? "△" : "·";
        lines.push(`    ${icon} ${sev.padEnd(10)} ${count}`);
      }
    }

    if (Object.keys(stats.eventCounts).length > 0) {
      lines.push(``);
      lines.push(`  By Event Type:`);
      for (const [type, count] of Object.entries(stats.eventCounts)) {
        lines.push(`    ${type.padEnd(24)} ${count}`);
      }
    }

    return lines.join("\n");
  }

  /**
   * Format recent events for CLI display.
   */
  formatRecent(count: number = 10): string {
    const recent = this.getRecent(count);
    if (recent.length === 0) return "  No perimeter events recorded.";

    const lines: string[] = [
      `  Recent Perimeter Events (last ${count}):`,
      `  ──────────────────────────────────────────────`,
    ];

    for (const entry of recent) {
      const sevIcon = entry.severity === "critical" ? "⊘" : entry.severity === "alert" ? "⚠" : entry.severity === "warn" ? "△" : "·";
      const time = entry.timestamp.replace("T", " ").substring(0, 19);
      const ip = entry.sourceIp ? ` [${entry.sourceIp}]` : "";
      lines.push(`  ${sevIcon} ${time}${ip} ${entry.eventType}: ${entry.description}`);
    }

    return lines.join("\n");
  }

  // ── Persistence ────────────────────────────────────────────

  private load(): PerimeterLedgerStore {
    try {
      if (fs.existsSync(LEDGER_PATH)) {
        const raw = fs.readFileSync(LEDGER_PATH, "utf-8");
        return JSON.parse(raw) as PerimeterLedgerStore;
      }
    } catch {
      // Corrupted — start fresh
    }
    return {
      version: "1.0.0",
      createdAt: new Date().toISOString(),
      entries: [],
    };
  }

  private persist(): void {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(LEDGER_PATH, JSON.stringify(this.store, null, 2), "utf-8");
    } catch (err) {
      console.error(`[Perimeter Ledger] Failed to persist:`, err);
    }
  }

  // ── Chain Hash ─────────────────────────────────────────────

  private getLastChainHash(): string {
    if (this.store.entries.length === 0) return GENESIS_HASH;
    return this.store.entries[this.store.entries.length - 1].chainHash;
  }

  private computeChainHash(
    entry: Omit<PerimeterEntry, "chainHash">,
    previousHash: string
  ): string {
    const data = `${entry.sequence}|${entry.entryId}|${entry.eventType}|${entry.timestamp}|${previousHash}`;
    return crypto.createHash("sha256").update(data).digest("hex");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: PerimeterLedger | null = null;
export function getPerimeterLedger(): PerimeterLedger {
  if (!_instance) _instance = new PerimeterLedger();
  return _instance;
}
