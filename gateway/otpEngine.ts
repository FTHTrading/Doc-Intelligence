// ─────────────────────────────────────────────────────────────
// OTP Engine — One-Time Password Verification
//
// TOTP-style OTP generation and verification for signer
// identity confirmation before signature submission.
//
// Features:
//   • 6-digit cryptographic OTP
//   • Configurable TTL (default 5 minutes)
//   • Rate limiting (max 5 attempts per OTP)
//   • Brute-force protection (lockout after 3 failures)
//   • Delivery-agnostic (returns OTP for any channel)
//   • Audit trail integration
//
// Flow:
//   1. Signer requests OTP → generate + send via channel
//   2. Signer enters OTP → verify
//   3. On success → unlock signature submission
//   4. On failure → increment attempt counter
//   5. On lockout → reject session for signer
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";

// ── Types ────────────────────────────────────────────────────

export type OTPStatus =
  | "pending"     // Generated, awaiting verification
  | "verified"    // Successfully verified
  | "expired"     // TTL elapsed
  | "failed"      // Max attempts exceeded
  | "locked-out"; // Too many failures, signer locked

/** A single OTP record */
export interface OTPRecord {
  /** Unique OTP ID */
  otpId: string;
  /** Session ID */
  sessionId: string;
  /** Signer ID */
  signerId: string;
  /** Signer email */
  signerEmail: string;
  /** OTP code (hashed after generation) */
  codeHash: string;
  /** Status */
  status: OTPStatus;
  /** Created at */
  createdAt: string;
  /** Expires at */
  expiresAt: string;
  /** Attempt count */
  attempts: number;
  /** Max attempts */
  maxAttempts: number;
  /** Verified at */
  verifiedAt?: string;
  /** Delivery channel used */
  deliveryChannel: string;
  /** IP of request */
  requestIp: string;
}

/** OTP generation result */
export interface OTPGenerationResult {
  /** The OTP code (plaintext, for sending — NOT stored) */
  code: string;
  /** OTP ID for tracking */
  otpId: string;
  /** Expiry timestamp */
  expiresAt: string;
  /** Whether this is a retry */
  isRetry: boolean;
  /** How many OTPs issued for this signer (this session) */
  issueCount: number;
}

/** OTP verification result */
export interface OTPVerificationResult {
  /** Whether verification succeeded */
  valid: boolean;
  /** OTP ID */
  otpId: string;
  /** Status message */
  message: string;
  /** Remaining attempts */
  remainingAttempts: number;
  /** Whether signer is locked out */
  lockedOut: boolean;
}

// ── OTP Engine ───────────────────────────────────────────────

interface OTPStore {
  engine: string;
  version: string;
  records: OTPRecord[];
}

const OTP_FILE = "otp-records.json";
const OTP_LENGTH = 6;
const OTP_TTL_SECONDS = 300; // 5 minutes
const MAX_ATTEMPTS = 5;
const MAX_ISSUES_PER_SESSION = 10;
const LOCKOUT_THRESHOLD = 3; // Lock after 3 failed OTPs

export class OTPEngine {
  private store: OTPStore;
  private storePath: string;

  constructor(storeDir: string = ".doc-engine") {
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.storePath = path.join(storeDir, OTP_FILE);
    this.store = this.load();
  }

  // ── Generate ─────────────────────────────────────────────

  /**
   * Generate a new OTP for a signer.
   */
  generate(params: {
    sessionId: string;
    signerId: string;
    signerEmail: string;
    deliveryChannel: string;
    requestIp: string;
    ttlSeconds?: number;
  }): OTPGenerationResult | { error: string } {
    // Check lockout
    const failedCount = this.getFailedOTPCount(params.sessionId, params.signerId);
    if (failedCount >= LOCKOUT_THRESHOLD) {
      return { error: `Signer locked out after ${LOCKOUT_THRESHOLD} failed OTP verifications` };
    }

    // Check issue limit
    const issueCount = this.getIssueCount(params.sessionId, params.signerId);
    if (issueCount >= MAX_ISSUES_PER_SESSION) {
      return { error: `Maximum OTP issues (${MAX_ISSUES_PER_SESSION}) reached for this session` };
    }

    // Expire any existing pending OTPs for this signer
    this.expirePending(params.sessionId, params.signerId);

    // Generate code
    const code = this.generateCode(OTP_LENGTH);
    const codeHash = this.hashCode(code);
    const ttl = params.ttlSeconds || OTP_TTL_SECONDS;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();

    const record: OTPRecord = {
      otpId: crypto.randomBytes(8).toString("hex"),
      sessionId: params.sessionId,
      signerId: params.signerId,
      signerEmail: params.signerEmail,
      codeHash,
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt,
      attempts: 0,
      maxAttempts: MAX_ATTEMPTS,
      deliveryChannel: params.deliveryChannel,
      requestIp: params.requestIp,
    };

    this.store.records.push(record);
    this.save();

    return {
      code,
      otpId: record.otpId,
      expiresAt,
      isRetry: issueCount > 0,
      issueCount: issueCount + 1,
    };
  }

  // ── Verify ───────────────────────────────────────────────

  /**
   * Verify an OTP code.
   */
  verify(params: {
    sessionId: string;
    signerId: string;
    code: string;
  }): OTPVerificationResult {
    // Check lockout first
    const failedCount = this.getFailedOTPCount(params.sessionId, params.signerId);
    if (failedCount >= LOCKOUT_THRESHOLD) {
      return {
        valid: false,
        otpId: "",
        message: "Signer is locked out",
        remainingAttempts: 0,
        lockedOut: true,
      };
    }

    // Find the most recent pending OTP for this signer
    const record = this.findPendingOTP(params.sessionId, params.signerId);
    if (!record) {
      return {
        valid: false,
        otpId: "",
        message: "No pending OTP found. Request a new one.",
        remainingAttempts: 0,
        lockedOut: false,
      };
    }

    // Check expiry
    if (new Date() > new Date(record.expiresAt)) {
      record.status = "expired";
      this.save();
      return {
        valid: false,
        otpId: record.otpId,
        message: "OTP expired. Request a new one.",
        remainingAttempts: 0,
        lockedOut: false,
      };
    }

    // Check code
    const codeHash = this.hashCode(params.code);
    record.attempts++;

    if (codeHash === record.codeHash) {
      record.status = "verified";
      record.verifiedAt = new Date().toISOString();
      this.save();
      return {
        valid: true,
        otpId: record.otpId,
        message: "OTP verified successfully",
        remainingAttempts: record.maxAttempts - record.attempts,
        lockedOut: false,
      };
    }

    // Wrong code
    if (record.attempts >= record.maxAttempts) {
      record.status = "failed";
      this.save();

      // Check if this triggers lockout
      const newFailedCount = this.getFailedOTPCount(params.sessionId, params.signerId);
      const lockedOut = newFailedCount >= LOCKOUT_THRESHOLD;

      return {
        valid: false,
        otpId: record.otpId,
        message: lockedOut ? "Maximum attempts exceeded. Signer locked out." : "Maximum attempts exceeded. Request a new OTP.",
        remainingAttempts: 0,
        lockedOut,
      };
    }

    this.save();
    return {
      valid: false,
      otpId: record.otpId,
      message: `Invalid OTP. ${record.maxAttempts - record.attempts} attempts remaining.`,
      remainingAttempts: record.maxAttempts - record.attempts,
      lockedOut: false,
    };
  }

  // ── Queries ──────────────────────────────────────────────

  /**
   * Check if a signer has a verified OTP for this session.
   */
  isVerified(sessionId: string, signerId: string): boolean {
    return this.store.records.some(
      (r) => r.sessionId === sessionId && r.signerId === signerId && r.status === "verified"
    );
  }

  /**
   * Check if a signer is locked out.
   */
  isLockedOut(sessionId: string, signerId: string): boolean {
    return this.getFailedOTPCount(sessionId, signerId) >= LOCKOUT_THRESHOLD;
  }

  /**
   * Get all OTP records for a signer in a session.
   */
  getRecords(sessionId: string, signerId: string): OTPRecord[] {
    return this.store.records.filter(
      (r) => r.sessionId === sessionId && r.signerId === signerId
    );
  }

  /**
   * Expire all stale OTPs globally.
   */
  expireStale(): number {
    let expired = 0;
    const now = new Date();
    for (const record of this.store.records) {
      if (record.status === "pending" && new Date(record.expiresAt) < now) {
        record.status = "expired";
        expired++;
      }
    }
    if (expired > 0) this.save();
    return expired;
  }

  // ── Internal ─────────────────────────────────────────────

  private generateCode(length: number): string {
    const max = Math.pow(10, length);
    const num = crypto.randomInt(0, max);
    return num.toString().padStart(length, "0");
  }

  private hashCode(code: string): string {
    return crypto.createHash("sha256").update(code).digest("hex");
  }

  private findPendingOTP(sessionId: string, signerId: string): OTPRecord | null {
    const records = this.store.records.filter(
      (r) => r.sessionId === sessionId && r.signerId === signerId && r.status === "pending"
    );
    return records.length > 0 ? records[records.length - 1] : null;
  }

  private getFailedOTPCount(sessionId: string, signerId: string): number {
    return this.store.records.filter(
      (r) => r.sessionId === sessionId && r.signerId === signerId && r.status === "failed"
    ).length;
  }

  private getIssueCount(sessionId: string, signerId: string): number {
    return this.store.records.filter(
      (r) => r.sessionId === sessionId && r.signerId === signerId
    ).length;
  }

  private expirePending(sessionId: string, signerId: string): void {
    for (const record of this.store.records) {
      if (
        record.sessionId === sessionId &&
        record.signerId === signerId &&
        record.status === "pending"
      ) {
        record.status = "expired";
      }
    }
    this.save();
  }

  private load(): OTPStore {
    if (fs.existsSync(this.storePath)) {
      try {
        return JSON.parse(fs.readFileSync(this.storePath, "utf-8"));
      } catch {
        // Corrupted — start fresh
      }
    }
    return { engine: "otp-engine", version: "1.0.0", records: [] };
  }

  private save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2));
  }
}

// ── Singleton ────────────────────────────────────────────────

let _otpEngine: OTPEngine | null = null;

export function getOTPEngine(): OTPEngine {
  if (!_otpEngine) {
    _otpEngine = new OTPEngine();
  }
  return _otpEngine;
}
