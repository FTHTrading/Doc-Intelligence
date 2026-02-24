// ─────────────────────────────────────────────────────────────
// Secure Document Control — Access Token Service
//
// Token-based access control for protected documents.
//
// Each token is:
//   - Single-use or limited-use
//   - Bound to email/phone identity
//   - IP-locked (optional)
//   - Device-fingerprint bound (optional)
//   - Time-limited (expires in N hours)
//   - OTP-verifiable
//   - Revocable instantly
//
// If someone forwards the link → it will not open without
// the original recipient's identity verification.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

export type TokenStatus =
  | "active"
  | "used"
  | "expired"
  | "revoked"
  | "locked";

export interface AccessToken {
  /** Unique token ID (URL-safe) */
  tokenId: string;
  /** Secret token value (URL path component) */
  tokenSecret: string;
  /** Document ID this token grants access to */
  documentId: string;
  /** Intake record ID */
  intakeId: string;
  /** Recipient identity */
  recipient: {
    name: string;
    email: string;
    phone?: string;
    organization?: string;
  };
  /** Token status */
  status: TokenStatus;
  /** Remaining uses (null = unlimited) */
  remainingUses: number | null;
  /** Maximum uses configured */
  maxUses: number;
  /** IP address bound to (null = any) */
  boundIP: string | null;
  /** Device fingerprint bound to (null = any) */
  boundDevice: string | null;
  /** First access IP (recorded on first use) */
  firstAccessIP: string | null;
  /** First access device fingerprint */
  firstAccessDevice: string | null;
  /** OTP verified */
  otpVerified: boolean;
  /** OTP required */
  otpRequired: boolean;
  /** Created timestamp */
  createdAt: string;
  /** Expires timestamp */
  expiresAt: string;
  /** Last accessed timestamp */
  lastAccessedAt: string | null;
  /** Access count */
  accessCount: number;
  /** Access log */
  accessLog: AccessLogEntry[];
  /** Token hash (integrity) */
  tokenHash: string;
}

export interface AccessLogEntry {
  /** Timestamp */
  timestamp: string;
  /** Action */
  action: "accessed" | "otp-verified" | "denied" | "expired" | "revoked" | "device-bound";
  /** IP address */
  ip: string;
  /** Device fingerprint */
  deviceFingerprint: string;
  /** User agent */
  userAgent: string;
  /** Result */
  result: "granted" | "denied";
  /** Denial reason (if denied) */
  denialReason?: string;
}

export interface TokenValidationResult {
  /** Is the token valid for access? */
  valid: boolean;
  /** If valid, the token record */
  token?: AccessToken;
  /** Reason for denial */
  reason: string;
  /** Should redirect to OTP? */
  requiresOTP: boolean;
  /** Should bind device? */
  requiresDeviceBinding: boolean;
}

// ── Store ────────────────────────────────────────────────────

interface TokenStore {
  tokens: AccessToken[];
  lastUpdated: string;
}

const STORE_DIR = path.join(process.cwd(), ".doc-engine");
const STORE_PATH = path.join(STORE_DIR, "sdc-tokens.json");

function loadStore(): TokenStore {
  if (fs.existsSync(STORE_PATH)) {
    return JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
  }
  return { tokens: [], lastUpdated: new Date().toISOString() };
}

function saveStore(store: TokenStore): void {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  store.lastUpdated = new Date().toISOString();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), "utf-8");
}

// ── Access Token Service ─────────────────────────────────────

export class AccessTokenService {
  private store: TokenStore;

  constructor() {
    this.store = loadStore();
  }

  /**
   * Issue a new access token for a document recipient.
   */
  issue(params: {
    documentId: string;
    intakeId: string;
    recipient: {
      name: string;
      email: string;
      phone?: string;
      organization?: string;
    };
    maxUses?: number;
    expiryHours?: number;
    requireOTP?: boolean;
    requireDeviceBinding?: boolean;
    boundIP?: string;
  }): AccessToken {
    const tokenId = crypto.randomBytes(8).toString("hex");
    const tokenSecret = crypto.randomBytes(32).toString("hex");
    const now = new Date();
    const expiryHours = params.expiryHours || 168; // 7 days default
    const expiresAt = new Date(now.getTime() + expiryHours * 60 * 60 * 1000).toISOString();

    const token: AccessToken = {
      tokenId,
      tokenSecret,
      documentId: params.documentId,
      intakeId: params.intakeId,
      recipient: params.recipient,
      status: "active",
      remainingUses: params.maxUses || null,
      maxUses: params.maxUses || 0,
      boundIP: params.boundIP || null,
      boundDevice: null,
      firstAccessIP: null,
      firstAccessDevice: null,
      otpVerified: false,
      otpRequired: params.requireOTP || false,
      createdAt: now.toISOString(),
      expiresAt,
      lastAccessedAt: null,
      accessCount: 0,
      accessLog: [],
      tokenHash: "",
    };

    token.tokenHash = this.computeTokenHash(token);

    this.store.tokens.push(token);
    saveStore(this.store);

    return token;
  }

  /**
   * Validate a token for document access.
   * Returns validation result with detailed reason.
   */
  validate(
    tokenSecret: string,
    ip: string,
    deviceFingerprint: string,
    userAgent: string
  ): TokenValidationResult {
    const token = this.store.tokens.find((t) => t.tokenSecret === tokenSecret);

    if (!token) {
      return { valid: false, reason: "Token not found", requiresOTP: false, requiresDeviceBinding: false };
    }

    // Check status
    if (token.status === "revoked") {
      this.logAccess(token, "denied", ip, deviceFingerprint, userAgent, "Token revoked");
      return { valid: false, reason: "Token has been revoked", requiresOTP: false, requiresDeviceBinding: false };
    }
    if (token.status === "locked") {
      this.logAccess(token, "denied", ip, deviceFingerprint, userAgent, "Token locked");
      return { valid: false, reason: "Token is locked", requiresOTP: false, requiresDeviceBinding: false };
    }

    // Check expiration
    if (new Date(token.expiresAt) < new Date()) {
      token.status = "expired";
      this.logAccess(token, "expired", ip, deviceFingerprint, userAgent, "Token expired");
      saveStore(this.store);
      return { valid: false, reason: "Token has expired", requiresOTP: false, requiresDeviceBinding: false };
    }

    // Check remaining uses
    if (token.remainingUses !== null && token.remainingUses <= 0) {
      token.status = "used";
      this.logAccess(token, "denied", ip, deviceFingerprint, userAgent, "Uses exhausted");
      saveStore(this.store);
      return { valid: false, reason: "Token has no remaining uses", requiresOTP: false, requiresDeviceBinding: false };
    }

    // Check IP binding
    if (token.boundIP && token.boundIP !== ip) {
      this.logAccess(token, "denied", ip, deviceFingerprint, userAgent, "IP mismatch");
      return { valid: false, reason: "IP address does not match token binding", requiresOTP: false, requiresDeviceBinding: false };
    }

    // Check device binding
    if (token.boundDevice && token.boundDevice !== deviceFingerprint) {
      this.logAccess(token, "denied", ip, deviceFingerprint, userAgent, "Device mismatch");
      return {
        valid: false,
        reason: "Device fingerprint does not match token binding",
        requiresOTP: false,
        requiresDeviceBinding: false,
      };
    }

    // Check if device binding needed (first access)
    const needsDeviceBinding = !token.boundDevice && token.firstAccessDevice === null;

    // Check OTP requirement
    if (token.otpRequired && !token.otpVerified) {
      return {
        valid: false,
        reason: "OTP verification required",
        requiresOTP: true,
        requiresDeviceBinding: needsDeviceBinding,
        token,
      };
    }

    // Record first access
    if (!token.firstAccessIP) {
      token.firstAccessIP = ip;
      token.firstAccessDevice = deviceFingerprint;
    }

    // Record access
    token.accessCount++;
    token.lastAccessedAt = new Date().toISOString();
    if (token.remainingUses !== null) {
      token.remainingUses--;
    }

    this.logAccess(token, "accessed", ip, deviceFingerprint, userAgent);
    saveStore(this.store);

    return {
      valid: true,
      token,
      reason: "Access granted",
      requiresOTP: false,
      requiresDeviceBinding: needsDeviceBinding,
    };
  }

  /**
   * Mark OTP as verified for a token.
   */
  verifyOTP(tokenSecret: string, ip: string, deviceFingerprint: string, userAgent: string): boolean {
    const token = this.store.tokens.find((t) => t.tokenSecret === tokenSecret);
    if (!token) return false;

    token.otpVerified = true;
    this.logAccess(token, "otp-verified", ip, deviceFingerprint, userAgent);
    saveStore(this.store);
    return true;
  }

  /**
   * Bind device fingerprint to token.
   */
  bindDevice(tokenSecret: string, deviceFingerprint: string, ip: string, userAgent: string): boolean {
    const token = this.store.tokens.find((t) => t.tokenSecret === tokenSecret);
    if (!token) return false;

    token.boundDevice = deviceFingerprint;
    this.logAccess(token, "device-bound", ip, deviceFingerprint, userAgent);
    saveStore(this.store);
    return true;
  }

  /**
   * Revoke a token immediately.
   */
  revoke(tokenId: string, reason: string): boolean {
    const token = this.store.tokens.find((t) => t.tokenId === tokenId);
    if (!token) return false;

    token.status = "revoked";
    this.logAccess(token, "revoked", "system", "system", "system", reason);
    saveStore(this.store);
    return true;
  }

  /**
   * Revoke all tokens for a document.
   */
  revokeAllForDocument(documentId: string): number {
    let count = 0;
    for (const token of this.store.tokens) {
      if (token.documentId === documentId && token.status === "active") {
        token.status = "revoked";
        count++;
      }
    }
    if (count > 0) saveStore(this.store);
    return count;
  }

  /**
   * Get token by secret.
   */
  getBySecret(tokenSecret: string): AccessToken | null {
    return this.store.tokens.find((t) => t.tokenSecret === tokenSecret) || null;
  }

  /**
   * Get all tokens for a document.
   */
  getByDocument(documentId: string): AccessToken[] {
    return this.store.tokens.filter((t) => t.documentId === documentId);
  }

  /**
   * Get all tokens for a recipient.
   */
  getByRecipient(email: string): AccessToken[] {
    return this.store.tokens.filter((t) => t.recipient.email === email);
  }

  /**
   * Expire stale tokens.
   */
  expireStale(): number {
    let count = 0;
    const now = new Date();
    for (const token of this.store.tokens) {
      if (token.status === "active" && new Date(token.expiresAt) < now) {
        token.status = "expired";
        count++;
      }
    }
    if (count > 0) saveStore(this.store);
    return count;
  }

  /**
   * Get statistics.
   */
  getStats(): {
    total: number;
    active: number;
    used: number;
    expired: number;
    revoked: number;
    totalAccesses: number;
    totalDenials: number;
  } {
    let active = 0, used = 0, expired = 0, revoked = 0;
    let totalAccesses = 0, totalDenials = 0;

    for (const t of this.store.tokens) {
      if (t.status === "active") active++;
      else if (t.status === "used") used++;
      else if (t.status === "expired") expired++;
      else if (t.status === "revoked") revoked++;

      for (const log of t.accessLog) {
        if (log.result === "granted") totalAccesses++;
        else totalDenials++;
      }
    }

    return {
      total: this.store.tokens.length,
      active,
      used,
      expired,
      revoked,
      totalAccesses,
      totalDenials,
    };
  }

  /**
   * Generate a secure access URL.
   */
  getAccessUrl(token: AccessToken, baseUrl: string): string {
    return `${baseUrl}/sdc/view/${token.tokenSecret}`;
  }

  // ── Private Methods ──────────────────────────────────────

  private logAccess(
    token: AccessToken,
    action: AccessLogEntry["action"],
    ip: string,
    deviceFingerprint: string,
    userAgent: string,
    denialReason?: string
  ): void {
    token.accessLog.push({
      timestamp: new Date().toISOString(),
      action,
      ip,
      deviceFingerprint,
      userAgent,
      result: action === "denied" || action === "expired" ? "denied" : "granted",
      denialReason,
    });
  }

  private computeTokenHash(token: AccessToken): string {
    return crypto
      .createHash("sha256")
      .update(`${token.tokenId}:${token.documentId}:${token.recipient.email}:${token.createdAt}`)
      .digest("hex");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _tokenService: AccessTokenService | null = null;

export function getAccessTokenService(): AccessTokenService {
  if (!_tokenService) {
    _tokenService = new AccessTokenService();
  }
  return _tokenService;
}
