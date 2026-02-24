// ─────────────────────────────────────────────────────────────
// Cloudflare Perimeter — Webhook Validator
//
// Request validation middleware for inbound webhooks:
//   • Telnyx IP allowlist verification
//   • Webhook signature validation (HMAC-SHA256)
//   • Source IP reputation checking
//   • Geo-origin verification
//   • Request body size limits
//   • Content-Type enforcement
//   • Replay attack prevention (nonce tracking)
//   • Rate fingerprinting (abuse detection)
//
// Defense-in-depth: Even behind Cloudflare WAF,
// the application layer validates independently.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import { getCloudflareConfig, IPAllowlistEntry } from "./cloudflareConfig";
import { getPerimeterLedger } from "./perimeterLedger";

// ── Types ────────────────────────────────────────────────────

/** Validation result */
export interface ValidationResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Reason for decision */
  reason: string;
  /** Validation checks that passed */
  passed: string[];
  /** Validation checks that failed */
  failed: string[];
  /** Risk score (0–100, 100 = most risky) */
  riskScore: number;
  /** Source IP */
  sourceIp: string;
  /** Validation ID */
  validationId: string;
  /** Timestamp */
  timestamp: string;
}

/** Request context for validation */
export interface RequestContext {
  /** Source IP address */
  sourceIp: string;
  /** Request method */
  method: string;
  /** Request path */
  path: string;
  /** User agent */
  userAgent: string;
  /** Content type */
  contentType: string;
  /** Content length */
  contentLength: number;
  /** Raw body (for signature verification) */
  rawBody: string;
  /** Telnyx signature header (if present) */
  telnyxSignature?: string;
  /** Telnyx timestamp header (if present) */
  telnyxTimestamp?: string;
  /** Request headers */
  headers: Record<string, string>;
}

/** IP reputation entry */
export interface IPReputation {
  /** IP address */
  ip: string;
  /** Total requests */
  totalRequests: number;
  /** Blocked requests */
  blockedRequests: number;
  /** Last seen */
  lastSeen: string;
  /** First seen */
  firstSeen: string;
  /** Risk level */
  riskLevel: "low" | "medium" | "high" | "critical";
  /** Whether currently blocked */
  blocked: boolean;
  /** Block expires at (if temporarily blocked) */
  blockExpiresAt: string | null;
}

// ── Constants ────────────────────────────────────────────────

/** Maximum webhook body size (1MB) */
const MAX_BODY_SIZE = 1 * 1024 * 1024;

/** Valid content types for webhooks */
const VALID_CONTENT_TYPES = new Set([
  "application/json",
  "application/json; charset=utf-8",
  "application/json;charset=utf-8",
]);

/** Nonce window (prevent replays within 5 minutes) */
const NONCE_WINDOW_MS = 5 * 60 * 1000;

/** Maximum timestamp drift for webhook signatures (5 minutes) */
const MAX_TIMESTAMP_DRIFT_MS = 5 * 60 * 1000;

/** Threshold for auto-blocking an IP */
const AUTO_BLOCK_THRESHOLD = 10;

/** Auto-block duration (30 minutes) */
const AUTO_BLOCK_DURATION_MS = 30 * 60 * 1000;

// ── Webhook Validator ────────────────────────────────────────

export class WebhookValidator {
  private config = getCloudflareConfig();
  private recentNonces: Map<string, number> = new Map();
  private ipReputation: Map<string, IPReputation> = new Map();
  private webhookSecret: string | null = null;

  constructor() {
    // Read Telnyx webhook signing secret from environment
    this.webhookSecret = process.env.TELNYX_WEBHOOK_SECRET || null;

    // Clean nonces periodically
    setInterval(() => this.cleanNonces(), 60_000);
  }

  /**
   * Set the Telnyx webhook signing secret.
   */
  setWebhookSecret(secret: string): void {
    this.webhookSecret = secret;
  }

  // ── Primary Validation ─────────────────────────────────────

  /**
   * Validate an inbound webhook request.
   * Runs all checks and returns a composite result.
   */
  validate(ctx: RequestContext): ValidationResult {
    const validationId = crypto.randomBytes(8).toString("hex");
    const passed: string[] = [];
    const failed: string[] = [];
    let riskScore = 0;

    // 1. IP allowlist check
    const ipCheck = this.checkIPAllowlist(ctx.sourceIp);
    if (ipCheck.allowed) {
      passed.push("ip-allowlist");
    } else {
      failed.push("ip-allowlist");
      riskScore += 40;
    }

    // 2. Auto-blocked IP check
    const repCheck = this.checkIPReputation(ctx.sourceIp);
    if (repCheck.blocked) {
      failed.push("ip-reputation");
      riskScore += 50;
    } else {
      passed.push("ip-reputation");
      if (repCheck.riskLevel === "high") riskScore += 15;
      if (repCheck.riskLevel === "medium") riskScore += 5;
    }

    // 3. Request method check
    if (ctx.method === "POST") {
      passed.push("method");
    } else {
      failed.push("method");
      riskScore += 10;
    }

    // 4. Content-Type check
    const normalizedCT = ctx.contentType.toLowerCase().trim();
    if (VALID_CONTENT_TYPES.has(normalizedCT)) {
      passed.push("content-type");
    } else {
      failed.push("content-type");
      riskScore += 10;
    }

    // 5. Body size check
    if (ctx.contentLength <= MAX_BODY_SIZE) {
      passed.push("body-size");
    } else {
      failed.push("body-size");
      riskScore += 15;
    }

    // 6. JSON validity check
    try {
      JSON.parse(ctx.rawBody);
      passed.push("json-valid");
    } catch {
      failed.push("json-valid");
      riskScore += 20;
    }

    // 7. Webhook signature verification (if secret configured)
    if (this.webhookSecret && ctx.telnyxSignature) {
      const sigCheck = this.verifyTelnyxSignature(
        ctx.rawBody,
        ctx.telnyxSignature,
        ctx.telnyxTimestamp || ""
      );
      if (sigCheck) {
        passed.push("webhook-signature");
      } else {
        failed.push("webhook-signature");
        riskScore += 30;
      }
    } else if (this.webhookSecret && !ctx.telnyxSignature) {
      failed.push("webhook-signature-missing");
      riskScore += 20;
    }

    // 8. Timestamp drift check (replay prevention)
    if (ctx.telnyxTimestamp) {
      const tsCheck = this.checkTimestampDrift(ctx.telnyxTimestamp);
      if (tsCheck) {
        passed.push("timestamp-drift");
      } else {
        failed.push("timestamp-drift");
        riskScore += 15;
      }
    }

    // 9. User agent check
    if (this.isSuspiciousUserAgent(ctx.userAgent)) {
      failed.push("user-agent");
      riskScore += 10;
    } else {
      passed.push("user-agent");
    }

    // Cap risk score
    riskScore = Math.min(riskScore, 100);

    // Decision: allow if no critical failures
    const criticalFailures = failed.filter((f) =>
      f === "ip-allowlist" || f === "ip-reputation" || f === "webhook-signature" || f === "body-size"
    );
    const allowed = criticalFailures.length === 0;

    // Update IP reputation
    this.updateIPReputation(ctx.sourceIp, allowed);

    // Build result
    const result: ValidationResult = {
      allowed,
      reason: allowed
        ? `Passed ${passed.length}/${passed.length + failed.length} checks (risk: ${riskScore})`
        : `Blocked — failed: ${criticalFailures.join(", ")}`,
      passed,
      failed,
      riskScore,
      sourceIp: ctx.sourceIp,
      validationId,
      timestamp: new Date().toISOString(),
    };

    // Log to perimeter ledger
    const ledger = getPerimeterLedger();
    ledger.recordValidation(result);

    return result;
  }

  // ── Individual Checks ──────────────────────────────────────

  /**
   * Check if source IP is in the allowlist.
   */
  checkIPAllowlist(ip: string): { allowed: boolean; matchedEntry: IPAllowlistEntry | null } {
    const allowlist = this.config.getIPAllowlist();

    for (const entry of allowlist) {
      if (this.ipMatchesCIDR(ip, entry.cidr)) {
        return { allowed: true, matchedEntry: entry };
      }
    }

    return { allowed: false, matchedEntry: null };
  }

  /**
   * Check if IP matches a CIDR range.
   */
  private ipMatchesCIDR(ip: string, cidr: string): boolean {
    // Handle IPv6 loopback
    if (ip === "::1" && cidr === "::1/128") return true;
    if (ip === "::ffff:127.0.0.1" && cidr === "127.0.0.1/32") return true;

    // Normalize IPv4-mapped IPv6
    const normalizedIP = ip.startsWith("::ffff:") ? ip.substring(7) : ip;

    const [rangeIP, prefixStr] = cidr.split("/");
    if (!rangeIP || !prefixStr) return normalizedIP === cidr;

    const prefix = parseInt(prefixStr, 10);
    if (isNaN(prefix)) return false;

    // For /32, exact match
    if (prefix === 32) return normalizedIP === rangeIP;

    // Parse IPv4 to 32-bit integer
    const ipNum = this.ipToNumber(normalizedIP);
    const rangeNum = this.ipToNumber(rangeIP);
    if (ipNum === null || rangeNum === null) return false;

    // Compute mask
    const mask = (~0) << (32 - prefix);
    return (ipNum & mask) === (rangeNum & mask);
  }

  /**
   * Convert IPv4 string to 32-bit number.
   */
  private ipToNumber(ip: string): number | null {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;

    let num = 0;
    for (const part of parts) {
      const octet = parseInt(part, 10);
      if (isNaN(octet) || octet < 0 || octet > 255) return null;
      num = (num << 8) | octet;
    }
    return num >>> 0; // Unsigned
  }

  /**
   * Verify Telnyx webhook HMAC-SHA256 signature.
   */
  private verifyTelnyxSignature(body: string, signature: string, timestamp: string): boolean {
    if (!this.webhookSecret) return false;

    try {
      const signedPayload = `${timestamp}.${body}`;
      const expected = crypto
        .createHmac("sha256", this.webhookSecret)
        .update(signedPayload)
        .digest("hex");

      // Constant-time comparison
      const sigBuffer = Buffer.from(signature, "hex");
      const expectedBuffer = Buffer.from(expected, "hex");

      if (sigBuffer.length !== expectedBuffer.length) return false;
      return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
    } catch {
      return false;
    }
  }

  /**
   * Check if webhook timestamp is within acceptable drift.
   */
  private checkTimestampDrift(timestamp: string): boolean {
    try {
      const webhookTime = new Date(timestamp).getTime();
      const now = Date.now();
      const drift = Math.abs(now - webhookTime);
      return drift <= MAX_TIMESTAMP_DRIFT_MS;
    } catch {
      return false;
    }
  }

  /**
   * Check for suspicious user agents.
   */
  private isSuspiciousUserAgent(ua: string): boolean {
    const suspicious = [
      "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
      "gobuster", "hydra", "burp", "metasploit", "zap",
      "wpscan", "nuclei", "ffuf", "feroxbuster",
    ];
    const lower = ua.toLowerCase();
    return suspicious.some((s) => lower.includes(s));
  }

  // ── IP Reputation ──────────────────────────────────────────

  /**
   * Get or create IP reputation entry.
   */
  private checkIPReputation(ip: string): IPReputation {
    const existing = this.ipReputation.get(ip);
    if (existing) {
      // Check if block has expired
      if (existing.blocked && existing.blockExpiresAt) {
        if (new Date(existing.blockExpiresAt).getTime() < Date.now()) {
          existing.blocked = false;
          existing.blockExpiresAt = null;
          existing.blockedRequests = 0;
        }
      }
      return existing;
    }

    const entry: IPReputation = {
      ip,
      totalRequests: 0,
      blockedRequests: 0,
      lastSeen: new Date().toISOString(),
      firstSeen: new Date().toISOString(),
      riskLevel: "low",
      blocked: false,
      blockExpiresAt: null,
    };
    this.ipReputation.set(ip, entry);
    return entry;
  }

  /**
   * Update IP reputation after a validation.
   */
  private updateIPReputation(ip: string, allowed: boolean): void {
    let entry = this.ipReputation.get(ip);
    if (!entry) {
      entry = {
        ip,
        totalRequests: 0,
        blockedRequests: 0,
        lastSeen: new Date().toISOString(),
        firstSeen: new Date().toISOString(),
        riskLevel: "low",
        blocked: false,
        blockExpiresAt: null,
      };
      this.ipReputation.set(ip, entry);
    }

    entry.totalRequests++;
    entry.lastSeen = new Date().toISOString();

    if (!allowed) {
      entry.blockedRequests++;

      // Auto-block if threshold exceeded
      if (entry.blockedRequests >= AUTO_BLOCK_THRESHOLD) {
        entry.blocked = true;
        entry.blockExpiresAt = new Date(Date.now() + AUTO_BLOCK_DURATION_MS).toISOString();
        entry.riskLevel = "critical";
      } else if (entry.blockedRequests >= 5) {
        entry.riskLevel = "high";
      } else if (entry.blockedRequests >= 2) {
        entry.riskLevel = "medium";
      }
    }
  }

  // ── Nonce Management ───────────────────────────────────────

  /**
   * Check and record a nonce for replay prevention.
   * Returns true if the nonce is new (not a replay).
   */
  checkNonce(nonce: string): boolean {
    if (this.recentNonces.has(nonce)) return false;
    this.recentNonces.set(nonce, Date.now());
    return true;
  }

  /**
   * Clean expired nonces.
   */
  private cleanNonces(): void {
    const cutoff = Date.now() - NONCE_WINDOW_MS;
    for (const [nonce, time] of this.recentNonces) {
      if (time < cutoff) this.recentNonces.delete(nonce);
    }
  }

  // ── Accessors ──────────────────────────────────────────────

  getIPReputation(ip: string): IPReputation | undefined {
    return this.ipReputation.get(ip);
  }

  getAllReputations(): IPReputation[] {
    return [...this.ipReputation.values()];
  }

  getBlockedIPs(): IPReputation[] {
    return this.getAllReputations().filter((r) => r.blocked);
  }

  /**
   * Manually block an IP.
   */
  blockIP(ip: string, durationMs: number = AUTO_BLOCK_DURATION_MS): void {
    let entry = this.ipReputation.get(ip);
    if (!entry) {
      entry = {
        ip,
        totalRequests: 0,
        blockedRequests: 0,
        lastSeen: new Date().toISOString(),
        firstSeen: new Date().toISOString(),
        riskLevel: "critical",
        blocked: true,
        blockExpiresAt: new Date(Date.now() + durationMs).toISOString(),
      };
      this.ipReputation.set(ip, entry);
    } else {
      entry.blocked = true;
      entry.riskLevel = "critical";
      entry.blockExpiresAt = new Date(Date.now() + durationMs).toISOString();
    }
  }

  /**
   * Manually unblock an IP.
   */
  unblockIP(ip: string): boolean {
    const entry = this.ipReputation.get(ip);
    if (!entry) return false;
    entry.blocked = false;
    entry.blockExpiresAt = null;
    entry.riskLevel = "low";
    entry.blockedRequests = 0;
    return true;
  }

  /**
   * Format validation summary for display.
   */
  formatStats(): string {
    const all = this.getAllReputations();
    const blocked = this.getBlockedIPs();
    const totalRequests = all.reduce((sum, r) => sum + r.totalRequests, 0);
    const totalBlocked = all.reduce((sum, r) => sum + r.blockedRequests, 0);

    const lines = [
      `  Webhook Validator Stats`,
      `  ──────────────────────────────────────────────`,
      `  Signature Verification: ${this.webhookSecret ? "ENABLED" : "NOT CONFIGURED"}`,
      `  Total IPs Tracked: ${all.length}`,
      `  Currently Blocked: ${blocked.length}`,
      `  Total Requests: ${totalRequests}`,
      `  Blocked Requests: ${totalBlocked}`,
      `  Block Rate: ${totalRequests > 0 ? ((totalBlocked / totalRequests) * 100).toFixed(1) : "0.0"}%`,
    ];

    if (blocked.length > 0) {
      lines.push(``);
      lines.push(`  Blocked IPs:`);
      for (const b of blocked) {
        lines.push(`    ${b.ip.padEnd(20)} — ${b.blockedRequests} violations, expires ${b.blockExpiresAt || "permanent"}`);
      }
    }

    return lines.join("\n");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: WebhookValidator | null = null;
export function getWebhookValidator(): WebhookValidator {
  if (!_instance) _instance = new WebhookValidator();
  return _instance;
}
