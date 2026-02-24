// ─────────────────────────────────────────────────────────────
// Signing Session — Sovereign Session Management
//
// A signing session represents a single document signing
// request sent to one or more parties. It tracks:
//
//   1. Session identity + secure access token
//   2. Required signers with contact channels
//   3. Required initials (section-level acknowledgments)
//   4. Signature collection status
//   5. Expiry / deadline enforcement
//   6. Threshold logic (N-of-M)
//   7. Intent records per signer
//   8. Distribution log (what was sent where)
//   9. Completion triggers (anchor, PDF, notify)
//
// One session = one document = one signing request.
// The session is the atomic unit of the gateway.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { SignatureType } from "../signature/signatureEngine";

// ── Types ────────────────────────────────────────────────────

/** Session status */
export type SessionStatus =
  | "created"        // Session created, not yet distributed
  | "distributed"    // Links sent to signers
  | "pending"        // Awaiting signatures
  | "partial"        // Some signatures collected
  | "threshold-met"  // Required threshold met
  | "completed"      // Finalized, anchored, archived
  | "expired"        // Deadline passed
  | "cancelled";     // Cancelled by creator

/** Contact channel for a signer */
export type ContactChannel = "email" | "sms" | "whatsapp" | "telegram" | "qr" | "wallet";

/** Individual signer in a session */
export interface SessionSigner {
  /** Unique signer ID within session */
  signerId: string;
  /** Display name */
  name: string;
  /** Email address (primary identifier) */
  email: string;
  /** Phone number (for SMS/WhatsApp) */
  phone?: string;
  /** Telegram handle */
  telegram?: string;
  /** Wallet address (for Web3 signing) */
  walletAddress?: string;
  /** Organization */
  organization?: string;
  /** Required role */
  role: string;
  /** Signature type */
  signatureType: SignatureType;
  /** Whether this signer is required (vs optional) */
  required: boolean;
  /** Preferred contact channels (ordered by priority) */
  channels: ContactChannel[];
  /** Secure access token for this signer */
  accessToken: string;
  /** Token expiry */
  tokenExpiresAt: string;
  /** Status */
  status: "pending" | "viewed" | "initialed" | "signed" | "rejected" | "expired";
  /** Sections that require initials from this signer */
  requiredInitials: string[];
  /** Sections already initialed */
  completedInitials: string[];
  /** Signed at timestamp */
  signedAt?: string;
  /** Signature hash */
  signatureHash?: string;
  /** Rejected at */
  rejectedAt?: string;
  /** Rejection reason */
  rejectionReason?: string;
  /** Distribution records: which channels were used */
  distributionLog: DistributionRecord[];
  /** View count */
  viewCount: number;
  /** Last viewed at */
  lastViewedAt?: string;
}

/** Record of a distribution attempt */
export interface DistributionRecord {
  /** Channel used */
  channel: ContactChannel;
  /** Sent at */
  sentAt: string;
  /** Delivery status */
  status: "sent" | "delivered" | "failed" | "bounced";
  /** Provider message ID (for tracking) */
  messageId?: string;
  /** Error message if failed */
  error?: string;
}

/** Session-level configuration */
export interface SessionConfig {
  /** Minimum signatures required */
  threshold: number;
  /** Require all signers (overrides threshold) */
  requireAll: boolean;
  /** Signing order: strict (sequential) or any (parallel) */
  ordering: "strict" | "any";
  /** Session expiry (ISO timestamp) */
  expiresAt: string;
  /** Auto-anchor on completion */
  autoAnchor: boolean;
  /** Auto-generate final PDF */
  autoFinalize: boolean;
  /** Auto-notify all parties on completion */
  autoNotify: boolean;
  /** Require intent confirmation checkbox */
  requireIntent: boolean;
  /** Require OTP verification */
  requireOTP: boolean;
  /** Base URL for signing links */
  baseUrl: string;
  /** Sections requiring initials (applies to all signers unless overridden) */
  requiredInitials: string[];
}

/** The signing session record */
export interface SigningSession {
  /** Unique session ID */
  sessionId: string;
  /** Associated document ID */
  documentId: string;
  /** Document title */
  documentTitle: string;
  /** Document hash at session creation */
  documentHash: string;
  /** Document SKU */
  sku?: string;
  /** Session configuration */
  config: SessionConfig;
  /** Creator identity */
  creator: {
    name: string;
    email: string;
    organization?: string;
  };
  /** All signers */
  signers: SessionSigner[];
  /** Current session status */
  status: SessionStatus;
  /** Current signature count */
  signatureCount: number;
  /** Whether threshold is met */
  thresholdMet: boolean;
  /** Created at */
  createdAt: string;
  /** Last activity */
  lastActivityAt: string;
  /** Completed at */
  completedAt?: string;
  /** Completion artifacts */
  artifacts?: {
    /** Final PDF path */
    finalPdf?: string;
    /** Signature certificate path */
    certificate?: string;
    /** Audit report path */
    auditReport?: string;
    /** IPFS CID */
    cid?: string;
    /** Ledger anchor TX */
    ledgerTx?: string;
    /** Merkle proof path */
    merkleProof?: string;
  };
  /** Session hash (integrity) */
  sessionHash: string;
}

// ── Session Engine ───────────────────────────────────────────

interface SessionStore {
  engine: string;
  version: string;
  sessions: SigningSession[];
}

const SESSION_FILE = "signing-sessions.json";
const DEFAULT_EXPIRY_HOURS = 72;
const DEFAULT_BASE_URL = "http://localhost:3002/sign";

export class SigningSessionEngine {
  private store: SessionStore;
  private storePath: string;

  constructor(storeDir: string = ".doc-engine") {
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.storePath = path.join(storeDir, SESSION_FILE);
    this.store = this.load();
  }

  // ── Session Creation ─────────────────────────────────────

  /**
   * Create a new signing session.
   */
  createSession(params: {
    documentId: string;
    documentTitle: string;
    documentHash: string;
    sku?: string;
    creator: { name: string; email: string; organization?: string };
    signers: Array<{
      name: string;
      email: string;
      phone?: string;
      telegram?: string;
      walletAddress?: string;
      organization?: string;
      role: string;
      signatureType?: SignatureType;
      required?: boolean;
      channels?: ContactChannel[];
      requiredInitials?: string[];
    }>;
    threshold?: number;
    requireAll?: boolean;
    ordering?: "strict" | "any";
    expiresInHours?: number;
    baseUrl?: string;
    requireIntent?: boolean;
    requireOTP?: boolean;
    autoAnchor?: boolean;
    autoFinalize?: boolean;
    autoNotify?: boolean;
    requiredInitials?: string[];
  }): SigningSession {
    const sessionId = crypto.randomBytes(16).toString("hex");
    const now = new Date();
    const expiryHours = params.expiresInHours || DEFAULT_EXPIRY_HOURS;
    const expiresAt = new Date(now.getTime() + expiryHours * 60 * 60 * 1000).toISOString();

    const signers: SessionSigner[] = params.signers.map((s) => ({
      signerId: crypto.randomBytes(8).toString("hex"),
      name: s.name,
      email: s.email,
      phone: s.phone,
      telegram: s.telegram,
      walletAddress: s.walletAddress,
      organization: s.organization,
      role: s.role,
      signatureType: s.signatureType || "counterparty",
      required: s.required !== false,
      channels: s.channels || ["email"],
      accessToken: crypto.randomBytes(32).toString("hex"),
      tokenExpiresAt: expiresAt,
      status: "pending",
      requiredInitials: s.requiredInitials || params.requiredInitials || [],
      completedInitials: [],
      distributionLog: [],
      viewCount: 0,
    }));

    const config: SessionConfig = {
      threshold: params.threshold || signers.filter((s) => s.required).length,
      requireAll: params.requireAll || false,
      ordering: params.ordering || "any",
      expiresAt,
      autoAnchor: params.autoAnchor !== false,
      autoFinalize: params.autoFinalize !== false,
      autoNotify: params.autoNotify !== false,
      requireIntent: params.requireIntent !== false,
      requireOTP: params.requireOTP || false,
      baseUrl: params.baseUrl || DEFAULT_BASE_URL,
      requiredInitials: params.requiredInitials || [],
    };

    const session: SigningSession = {
      sessionId,
      documentId: params.documentId,
      documentTitle: params.documentTitle,
      documentHash: params.documentHash,
      sku: params.sku,
      config,
      creator: params.creator,
      signers,
      status: "created",
      signatureCount: 0,
      thresholdMet: false,
      createdAt: now.toISOString(),
      lastActivityAt: now.toISOString(),
      sessionHash: "",
    };

    session.sessionHash = this.computeSessionHash(session);

    this.store.sessions.push(session);
    this.save();
    return session;
  }

  // ── Token Resolution ─────────────────────────────────────

  /**
   * Resolve an access token to a session + signer.
   */
  resolveToken(token: string): { session: SigningSession; signer: SessionSigner } | null {
    for (const session of this.store.sessions) {
      if (session.status === "expired" || session.status === "cancelled") continue;
      for (const signer of session.signers) {
        if (signer.accessToken === token) {
          // Check expiry
          if (new Date() > new Date(signer.tokenExpiresAt)) {
            signer.status = "expired";
            this.save();
            return null;
          }
          return { session, signer };
        }
      }
    }
    return null;
  }

  // ── Signer Actions ───────────────────────────────────────

  /**
   * Record that a signer viewed the document.
   */
  recordView(sessionId: string, signerId: string, ip?: string): boolean {
    const session = this.getSession(sessionId);
    if (!session) return false;
    const signer = session.signers.find((s) => s.signerId === signerId);
    if (!signer) return false;

    signer.viewCount++;
    signer.lastViewedAt = new Date().toISOString();
    if (signer.status === "pending") signer.status = "viewed";
    session.lastActivityAt = new Date().toISOString();

    this.save();
    return true;
  }

  /**
   * Record an initial on a specific section.
   */
  recordInitial(sessionId: string, signerId: string, sectionId: string): {
    success: boolean;
    message: string;
    remainingInitials: string[];
  } {
    const session = this.getSession(sessionId);
    if (!session) return { success: false, message: "Session not found", remainingInitials: [] };
    const signer = session.signers.find((s) => s.signerId === signerId);
    if (!signer) return { success: false, message: "Signer not found", remainingInitials: [] };

    if (signer.status === "signed" || signer.status === "rejected" || signer.status === "expired") {
      return { success: false, message: `Signer status is ${signer.status}`, remainingInitials: [] };
    }

    if (!signer.requiredInitials.includes(sectionId)) {
      return { success: false, message: "Section not in required initials", remainingInitials: signer.requiredInitials.filter((s) => !signer.completedInitials.includes(s)) };
    }

    if (signer.completedInitials.includes(sectionId)) {
      return { success: false, message: "Section already initialed", remainingInitials: signer.requiredInitials.filter((s) => !signer.completedInitials.includes(s)) };
    }

    signer.completedInitials.push(sectionId);
    if (signer.status === "pending" || signer.status === "viewed") signer.status = "initialed";
    session.lastActivityAt = new Date().toISOString();
    this.save();

    const remaining = signer.requiredInitials.filter((s) => !signer.completedInitials.includes(s));
    return { success: true, message: `Initialed ${sectionId}`, remainingInitials: remaining };
  }

  /**
   * Record a signer's signature.
   */
  recordSignature(
    sessionId: string,
    signerId: string,
    signatureHash: string
  ): {
    success: boolean;
    message: string;
    sessionStatus: SessionStatus;
    thresholdMet: boolean;
  } {
    const session = this.getSession(sessionId);
    if (!session) return { success: false, message: "Session not found", sessionStatus: "pending", thresholdMet: false };

    const signer = session.signers.find((s) => s.signerId === signerId);
    if (!signer) return { success: false, message: "Signer not found", sessionStatus: session.status, thresholdMet: session.thresholdMet };

    // Check status
    if (signer.status === "signed") return { success: false, message: "Already signed", sessionStatus: session.status, thresholdMet: session.thresholdMet };
    if (signer.status === "rejected") return { success: false, message: "Signer rejected", sessionStatus: session.status, thresholdMet: session.thresholdMet };
    if (signer.status === "expired") return { success: false, message: "Token expired", sessionStatus: session.status, thresholdMet: session.thresholdMet };

    // Check required initials
    const remainingInitials = signer.requiredInitials.filter((s) => !signer.completedInitials.includes(s));
    if (remainingInitials.length > 0) {
      return {
        success: false,
        message: `Must initial ${remainingInitials.length} sections before signing: ${remainingInitials.join(", ")}`,
        sessionStatus: session.status,
        thresholdMet: session.thresholdMet,
      };
    }

    // Check ordering
    if (session.config.ordering === "strict") {
      const signerIndex = session.signers.indexOf(signer);
      for (let i = 0; i < signerIndex; i++) {
        if (session.signers[i].required && session.signers[i].status !== "signed") {
          return {
            success: false,
            message: `Strict ordering: ${session.signers[i].name} must sign first`,
            sessionStatus: session.status,
            thresholdMet: session.thresholdMet,
          };
        }
      }
    }

    // Record signature
    signer.status = "signed";
    signer.signedAt = new Date().toISOString();
    signer.signatureHash = signatureHash;
    session.signatureCount++;
    session.lastActivityAt = new Date().toISOString();

    // Check threshold
    const requiredSigned = session.signers.filter((s) => s.required && s.status === "signed").length;
    const totalRequired = session.config.requireAll
      ? session.signers.filter((s) => s.required).length
      : session.config.threshold;

    session.thresholdMet = requiredSigned >= totalRequired;

    // Update session status
    if (session.thresholdMet) {
      session.status = "threshold-met";
    } else if (session.signatureCount > 0) {
      session.status = "partial";
    }

    this.save();

    return {
      success: true,
      message: `Signature recorded (${session.signatureCount}/${totalRequired})`,
      sessionStatus: session.status,
      thresholdMet: session.thresholdMet,
    };
  }

  /**
   * Record a rejection.
   */
  recordRejection(sessionId: string, signerId: string, reason: string): {
    success: boolean;
    message: string;
  } {
    const session = this.getSession(sessionId);
    if (!session) return { success: false, message: "Session not found" };

    const signer = session.signers.find((s) => s.signerId === signerId);
    if (!signer) return { success: false, message: "Signer not found" };

    signer.status = "rejected";
    signer.rejectedAt = new Date().toISOString();
    signer.rejectionReason = reason;
    session.lastActivityAt = new Date().toISOString();

    // If required signer rejected, check if threshold is still achievable
    const remainingRequired = session.signers.filter(
      (s) => s.required && s.status !== "signed" && s.status !== "rejected"
    ).length;
    const signedCount = session.signers.filter((s) => s.required && s.status === "signed").length;
    const totalNeeded = session.config.requireAll
      ? session.signers.filter((s) => s.required).length
      : session.config.threshold;

    if (signedCount + remainingRequired < totalNeeded) {
      // Threshold can no longer be met
      session.status = "cancelled";
    }

    this.save();
    return { success: true, message: `Rejection recorded: ${reason}` };
  }

  /**
   * Mark session as completed with artifacts.
   */
  completeSession(
    sessionId: string,
    artifacts: SigningSession["artifacts"]
  ): boolean {
    const session = this.getSession(sessionId);
    if (!session) return false;
    if (!session.thresholdMet) return false;

    session.status = "completed";
    session.completedAt = new Date().toISOString();
    session.artifacts = artifacts;
    session.sessionHash = this.computeSessionHash(session);
    this.save();
    return true;
  }

  /**
   * Mark a distribution record for a signer.
   */
  recordDistribution(
    sessionId: string,
    signerId: string,
    record: DistributionRecord
  ): boolean {
    const session = this.getSession(sessionId);
    if (!session) return false;
    const signer = session.signers.find((s) => s.signerId === signerId);
    if (!signer) return false;

    signer.distributionLog.push(record);
    if (session.status === "created") session.status = "distributed";
    session.lastActivityAt = new Date().toISOString();
    this.save();
    return true;
  }

  // ── Queries ──────────────────────────────────────────────

  getSession(sessionId: string): SigningSession | null {
    return this.store.sessions.find((s) => s.sessionId === sessionId) || null;
  }

  getSessionByDocument(documentId: string): SigningSession | null {
    return this.store.sessions.find((s) => s.documentId === documentId && s.status !== "cancelled" && s.status !== "expired") || null;
  }

  getActiveSessions(): SigningSession[] {
    return this.store.sessions.filter((s) =>
      s.status !== "completed" && s.status !== "cancelled" && s.status !== "expired"
    );
  }

  getAllSessions(): SigningSession[] {
    return [...this.store.sessions];
  }

  /**
   * Get signing URL for a signer.
   */
  getSigningUrl(session: SigningSession, signer: SessionSigner): string {
    return `${session.config.baseUrl}/${signer.accessToken}`;
  }

  /**
   * Get session stats.
   */
  getStats(): {
    total: number;
    active: number;
    completed: number;
    expired: number;
    cancelled: number;
    totalSignatures: number;
  } {
    const sessions = this.store.sessions;
    return {
      total: sessions.length,
      active: sessions.filter((s) => !["completed", "expired", "cancelled"].includes(s.status)).length,
      completed: sessions.filter((s) => s.status === "completed").length,
      expired: sessions.filter((s) => s.status === "expired").length,
      cancelled: sessions.filter((s) => s.status === "cancelled").length,
      totalSignatures: sessions.reduce((sum, s) => sum + s.signatureCount, 0),
    };
  }

  /**
   * Expire all sessions past their deadline.
   */
  expireStale(): number {
    let expired = 0;
    const now = new Date();
    for (const session of this.store.sessions) {
      if (
        session.status !== "completed" &&
        session.status !== "cancelled" &&
        session.status !== "expired" &&
        new Date(session.config.expiresAt) < now
      ) {
        session.status = "expired";
        for (const signer of session.signers) {
          if (signer.status === "pending" || signer.status === "viewed" || signer.status === "initialed") {
            signer.status = "expired";
          }
        }
        expired++;
      }
    }
    if (expired > 0) this.save();
    return expired;
  }

  /**
   * Format a session summary.
   */
  formatSessionSummary(session: SigningSession): string {
    const lines: string[] = [];
    lines.push(`  Session: ${session.sessionId.substring(0, 16)}...`);
    lines.push(`  Document: ${session.documentTitle}`);
    lines.push(`  Status: ${session.status.toUpperCase()}`);
    lines.push(`  Threshold: ${session.signatureCount}/${session.config.threshold}`);
    lines.push(`  Expires: ${session.config.expiresAt}`);
    lines.push(`  Signers:`);
    for (const signer of session.signers) {
      const icon = signer.status === "signed" ? "✓" : signer.status === "rejected" ? "✗" : "○";
      const channels = signer.channels.join(", ");
      lines.push(`    [${icon}] ${signer.name} (${signer.email}) — ${signer.status} [${channels}]`);
      if (signer.requiredInitials.length > 0) {
        lines.push(`        Initials: ${signer.completedInitials.length}/${signer.requiredInitials.length}`);
      }
      if (signer.distributionLog.length > 0) {
        const lastDist = signer.distributionLog[signer.distributionLog.length - 1];
        lines.push(`        Last sent: ${lastDist.channel} (${lastDist.status}) at ${lastDist.sentAt}`);
      }
    }
    if (session.artifacts) {
      lines.push(`  Artifacts:`);
      if (session.artifacts.finalPdf) lines.push(`    PDF: ${session.artifacts.finalPdf}`);
      if (session.artifacts.certificate) lines.push(`    Certificate: ${session.artifacts.certificate}`);
      if (session.artifacts.cid) lines.push(`    CID: ${session.artifacts.cid}`);
    }
    return lines.join("\n");
  }

  // ── Internal ─────────────────────────────────────────────

  private computeSessionHash(session: SigningSession): string {
    const payload = JSON.stringify({
      sessionId: session.sessionId,
      documentId: session.documentId,
      documentHash: session.documentHash,
      status: session.status,
      signatureCount: session.signatureCount,
      signers: session.signers.map((s) => `${s.email}:${s.status}:${s.signatureHash || "none"}`),
    });
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  private load(): SessionStore {
    if (fs.existsSync(this.storePath)) {
      try {
        return JSON.parse(fs.readFileSync(this.storePath, "utf-8"));
      } catch {
        // Corrupted — start fresh
      }
    }
    return { engine: "signing-session-engine", version: "1.0.0", sessions: [] };
  }

  private save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2));
  }
}

// ── Singleton ────────────────────────────────────────────────

let _sessionEngine: SigningSessionEngine | null = null;

export function getSigningSessionEngine(): SigningSessionEngine {
  if (!_sessionEngine) {
    _sessionEngine = new SigningSessionEngine();
  }
  return _sessionEngine;
}
