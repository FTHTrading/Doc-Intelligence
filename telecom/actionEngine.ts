// ─────────────────────────────────────────────────────────────
// Sovereign Comms Agent — Action Engine
//
// Executes actions based on classified intent.
// This is the bridge between the AI Intent Engine and the
// existing gateway infrastructure:
//
//   Intent → Action → Gateway → Response
//
// Each action is logged, governance-gated, and produces an
// ActionResult that the Response Composer uses to build
// the outbound reply.
//
// Governance enforcement:
//   Tier 0–1: Execute immediately
//   Tier 2:   Queue for approval, notify operator
//   Tier 3:   Reject, escalate to human
//
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import { InboundMessage, sendTelnyxMessage, OutboundMessage } from "./inboundRouter";
import { IntentResult, IntentCategory, GovernanceTier } from "./aiIntentEngine";
import { TelecomNumber, getTelecomRegistry } from "./telecomRegistry";
import { getSigningSessionEngine, SigningSession, SessionSigner } from "../gateway/signingSession";
import { getOTPEngine, OTPGenerationResult, OTPVerificationResult } from "../gateway/otpEngine";
import fs from "fs";
import path from "path";

// ── Types ────────────────────────────────────────────────────

/** Result of an action execution */
export interface ActionResult {
  /** Unique action ID */
  actionId: string;
  /** The intent that triggered this action */
  intent: IntentCategory;
  /** Governance tier applied */
  tier: GovernanceTier;
  /** Whether the action executed */
  executed: boolean;
  /** Action status */
  status: "completed" | "queued" | "escalated" | "denied" | "error";
  /** Human-readable summary */
  summary: string;
  /** Data for response composition */
  responseData: Record<string, unknown>;
  /** Whether a response SMS should be sent */
  shouldRespond: boolean;
  /** Suggested response message (pre-formatted if simple) */
  suggestedResponse?: string;
  /** Escalation target (if escalated) */
  escalationTarget?: string;
  /** Timestamp */
  timestamp: string;
}

/** Pending approval record */
export interface PendingApproval {
  /** Unique approval ID */
  approvalId: string;
  /** The action waiting for approval */
  actionId: string;
  /** Intent classification */
  intent: IntentCategory;
  /** Tier level */
  tier: GovernanceTier;
  /** Original inbound message */
  from: string;
  /** Target number */
  to: string;
  /** Original message text */
  messageText: string;
  /** Suggested action */
  suggestedAction: string;
  /** Extracted entities */
  entities: Record<string, unknown>;
  /** Status */
  status: "pending" | "approved" | "rejected" | "expired";
  /** Created at */
  createdAt: string;
  /** Resolved at */
  resolvedAt?: string;
  /** Resolved by */
  resolvedBy?: string;
  /** Expiry (24h from creation) */
  expiresAt: string;
}

/** Approval store */
interface ApprovalStore {
  engine: string;
  version: string;
  approvals: PendingApproval[];
}

const APPROVAL_FILE = "sca-pending-approvals.json";
const APPROVAL_TTL_HOURS = 24;

// ── Action Engine ────────────────────────────────────────────

export class ActionEngine {
  private approvalStore: ApprovalStore;
  private approvalPath: string;

  constructor(storeDir: string = ".doc-engine") {
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.approvalPath = path.join(storeDir, APPROVAL_FILE);
    this.approvalStore = this.loadApprovals();
  }

  // ── Main Dispatch ──────────────────────────────────────────

  /**
   * Execute an action based on classified intent.
   */
  async execute(
    intent: IntentResult,
    message: InboundMessage
  ): Promise<ActionResult> {
    const actionId = crypto.randomBytes(8).toString("hex");
    const timestamp = new Date().toISOString();

    // ── Governance Gate ──
    if (intent.tier >= 3) {
      return this.escalate(actionId, intent, message, timestamp);
    }

    if (intent.tier >= 2) {
      return this.queueForApproval(actionId, intent, message, timestamp);
    }

    // ── Tier 0–1: Execute ──
    try {
      switch (intent.intent) {
        case "status":
          return this.handleStatus(actionId, intent, message, timestamp);
        case "help":
          return this.handleHelp(actionId, intent, message, timestamp);
        case "sign":
          return this.handleSign(actionId, intent, message, timestamp);
        case "otp":
          return this.handleOTP(actionId, intent, message, timestamp);
        case "verify":
          return this.handleVerify(actionId, intent, message, timestamp);
        case "documents":
          return this.handleDocuments(actionId, intent, message, timestamp);
        case "confirm":
          return this.handleConfirm(actionId, intent, message, timestamp);
        case "deny":
          return this.handleDeny(actionId, intent, message, timestamp);
        default:
          return this.escalate(actionId, intent, message, timestamp);
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Unknown error";
      return {
        actionId,
        intent: intent.intent,
        tier: intent.tier,
        executed: false,
        status: "error",
        summary: `Action failed: ${errorMsg}`,
        responseData: { error: errorMsg },
        shouldRespond: true,
        suggestedResponse: "An error occurred processing your request. Please try again or reply HELP.",
        timestamp,
      };
    }
  }

  // ── Intent Handlers ────────────────────────────────────────

  /**
   * STATUS — Check signing session or deal status.
   */
  private handleStatus(
    actionId: string,
    intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const sessionEngine = getSigningSessionEngine();
    const sessionId = intent.entities.sessionId;
    const dealId = intent.entities.dealId;

    // Try by session ID first
    if (sessionId) {
      const session = sessionEngine.getSession(sessionId);
      if (session) {
        return {
          actionId,
          intent: "status",
          tier: 0,
          executed: true,
          status: "completed",
          summary: `Status check for session ${sessionId}`,
          responseData: this.summarizeSession(session),
          shouldRespond: true,
          suggestedResponse: this.formatSessionStatus(session),
          timestamp,
        };
      }
    }

    // Try active sessions for this sender
    const activeSessions = sessionEngine.getActiveSessions();
    const senderSessions = activeSessions.filter((s) =>
      s.signers.some((signer) => signer.phone === message.from)
    );

    if (senderSessions.length > 0) {
      const latest = senderSessions[senderSessions.length - 1];
      return {
        actionId,
        intent: "status",
        tier: 0,
        executed: true,
        status: "completed",
        summary: `Found ${senderSessions.length} active session(s) for ${message.from}`,
        responseData: {
          sessionCount: senderSessions.length,
          latest: this.summarizeSession(latest),
        },
        shouldRespond: true,
        suggestedResponse: senderSessions.length === 1
          ? this.formatSessionStatus(latest)
          : `You have ${senderSessions.length} active sessions. Latest: "${latest.documentTitle}" — Status: ${latest.status.toUpperCase()}. Reply STATUS <session-id> for details.`,
        timestamp,
      };
    }

    return {
      actionId,
      intent: "status",
      tier: 0,
      executed: true,
      status: "completed",
      summary: "No active sessions found for sender",
      responseData: { found: false },
      shouldRespond: true,
      suggestedResponse: "No active signing sessions found for your number. Reply HELP for more options.",
      timestamp,
    };
  }

  /**
   * HELP — Send contextual help based on number mode.
   */
  private handleHelp(
    actionId: string,
    intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const number = message.targetNumber;
    const mode = number?.mode || "INFRA";
    const persona = number?.persona;

    const helpText = this.getHelp(mode);
    const greeting = persona?.greeting || "FTH Trading Sovereign Comms";

    return {
      actionId,
      intent: "help",
      tier: 0,
      executed: true,
      status: "completed",
      summary: `Help response for ${mode} number`,
      responseData: { mode, helpText },
      shouldRespond: true,
      suggestedResponse: `${greeting}\n\n${helpText}\n\nReply STOP to opt out.`,
      timestamp,
    };
  }

  /**
   * SIGN — Find or create signing session, generate link.
   */
  private handleSign(
    actionId: string,
    intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const sessionEngine = getSigningSessionEngine();

    // Look for the sender's active sessions
    const activeSessions = sessionEngine.getActiveSessions();
    const senderSessions = activeSessions.filter((s) =>
      s.signers.some((signer) => signer.phone === message.from)
    );

    if (senderSessions.length === 0) {
      return {
        actionId,
        intent: "sign",
        tier: 1,
        executed: true,
        status: "completed",
        summary: "No active signing session found for sender",
        responseData: { found: false },
        shouldRespond: true,
        suggestedResponse: "No pending signing requests found for your number. If you received a signing invitation, please check the link sent to your email.",
        timestamp,
      };
    }

    // Find the session and signer
    const session = senderSessions[0];
    const signer = session.signers.find((s) => s.phone === message.from);
    if (!signer) {
      return {
        actionId,
        intent: "sign",
        tier: 1,
        executed: false,
        status: "error",
        summary: "Signer not found in session",
        responseData: { error: "signer-not-found" },
        shouldRespond: true,
        suggestedResponse: "Unable to locate your signing record. Please contact support.",
        timestamp,
      };
    }

    const signingUrl = sessionEngine.getSigningUrl(session, signer);
    const requiresOTP = session.config.requireOTP;

    return {
      actionId,
      intent: "sign",
      tier: 1,
      executed: true,
      status: "completed",
      summary: `Signing link generated for ${signer.name} — session ${session.sessionId}`,
      responseData: {
        sessionId: session.sessionId,
        documentTitle: session.documentTitle,
        signerName: signer.name,
        signingUrl,
        requiresOTP,
        status: signer.status,
      },
      shouldRespond: true,
      suggestedResponse: requiresOTP
        ? `Your signing link for "${session.documentTitle}" is ready. An OTP verification code will be sent to confirm your identity before signing. ${signingUrl}`
        : `Your signing link for "${session.documentTitle}": ${signingUrl}\n\nThis link expires ${session.config.expiresAt}.`,
      timestamp,
    };
  }

  /**
   * OTP — Verify a one-time password.
   */
  private handleOTP(
    actionId: string,
    intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const code = intent.entities.otpCode;
    if (!code) {
      return {
        actionId,
        intent: "otp",
        tier: 1,
        executed: false,
        status: "error",
        summary: "No OTP code found in message",
        responseData: { error: "no-code" },
        shouldRespond: true,
        suggestedResponse: "Please send your 6-digit verification code.",
        timestamp,
      };
    }

    const otpEngine = getOTPEngine();
    const sessionEngine = getSigningSessionEngine();

    // Find active session for this sender
    const activeSessions = sessionEngine.getActiveSessions();
    const senderSession = activeSessions.find((s) =>
      s.signers.some((signer) => signer.phone === message.from)
    );

    if (!senderSession) {
      return {
        actionId,
        intent: "otp",
        tier: 1,
        executed: false,
        status: "error",
        summary: "No active session for OTP verification",
        responseData: { error: "no-session" },
        shouldRespond: true,
        suggestedResponse: "No active session found. OTP verification requires an active signing session.",
        timestamp,
      };
    }

    const signer = senderSession.signers.find((s) => s.phone === message.from);
    if (!signer) {
      return {
        actionId,
        intent: "otp",
        tier: 1,
        executed: false,
        status: "error",
        summary: "Signer not found",
        responseData: { error: "signer-not-found" },
        shouldRespond: true,
        suggestedResponse: "Unable to verify. Please contact support.",
        timestamp,
      };
    }

    const result: OTPVerificationResult = otpEngine.verify({
      sessionId: senderSession.sessionId,
      signerId: signer.signerId,
      code,
    });

    if (result.valid) {
      const signingUrl = sessionEngine.getSigningUrl(senderSession, signer);
      return {
        actionId,
        intent: "otp",
        tier: 1,
        executed: true,
        status: "completed",
        summary: `OTP verified for ${signer.name}`,
        responseData: {
          verified: true,
          sessionId: senderSession.sessionId,
          signerName: signer.name,
          signingUrl,
        },
        shouldRespond: true,
        suggestedResponse: `Identity verified. You may now sign "${senderSession.documentTitle}": ${signingUrl}`,
        timestamp,
      };
    }

    return {
      actionId,
      intent: "otp",
      tier: 1,
      executed: true,
      status: "completed",
      summary: `OTP verification failed: ${result.message}`,
      responseData: {
        verified: false,
        message: result.message,
        remainingAttempts: result.remainingAttempts,
        lockedOut: result.lockedOut,
      },
      shouldRespond: true,
      suggestedResponse: result.lockedOut
        ? "Too many failed attempts. Your session has been locked. Please contact support."
        : `Incorrect code. ${result.remainingAttempts} attempt(s) remaining. Please try again.`,
      timestamp,
    };
  }

  /**
   * VERIFY — Verify a document or signature.
   */
  private handleVerify(
    actionId: string,
    intent: IntentResult,
    _message: InboundMessage,
    timestamp: string
  ): ActionResult {
    // For document verification via SMS, we direct them to the secure viewer
    const docRef = intent.entities.referenceNumber || intent.entities.documentTitle;

    return {
      actionId,
      intent: "verify",
      tier: 1,
      executed: true,
      status: "completed",
      summary: `Verification request${docRef ? ` for ${docRef}` : ""}`,
      responseData: { reference: docRef },
      shouldRespond: true,
      suggestedResponse: docRef
        ? `To verify document "${docRef}", visit: https://verify.fthtrading.com/${docRef}\n\nFor signature verification, include the signature hash.`
        : "To verify a document, reply: VERIFY <reference-number>\n\nYou can find the reference number on your signed document.",
      timestamp,
    };
  }

  /**
   * DOCUMENTS — Send document package.
   */
  private handleDocuments(
    actionId: string,
    intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const mode = message.targetNumber?.mode || "INFRA";
    const dealId = intent.entities.dealId || message.targetNumber?.dealId;

    return {
      actionId,
      intent: "documents",
      tier: 1,
      executed: true,
      status: "completed",
      summary: `Document request${dealId ? ` for deal ${dealId}` : ""}`,
      responseData: { mode, dealId },
      shouldRespond: true,
      suggestedResponse: dealId
        ? `Document package for deal ${dealId} is being prepared. You will receive a secure download link shortly.`
        : `To request documents, reply: DOCS <deal-id>\n\nAvailable document packages:\n• Investor Pack\n• Compliance Bundle\n• Offering Memorandum`,
      timestamp,
    };
  }

  /**
   * CONFIRM — Confirm a pending action.
   */
  private handleConfirm(
    actionId: string,
    _intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    // Check for pending approvals from this sender
    const pending = this.approvalStore.approvals.find(
      (a) => a.from === message.from && a.status === "pending"
    );

    if (!pending) {
      return {
        actionId,
        intent: "confirm",
        tier: 1,
        executed: true,
        status: "completed",
        summary: "No pending action to confirm",
        responseData: { found: false },
        shouldRespond: true,
        suggestedResponse: "No pending actions to confirm. Reply HELP for available commands.",
        timestamp,
      };
    }

    pending.status = "approved";
    pending.resolvedAt = timestamp;
    pending.resolvedBy = message.from;
    this.saveApprovals();

    return {
      actionId,
      intent: "confirm",
      tier: 1,
      executed: true,
      status: "completed",
      summary: `Approved pending action: ${pending.suggestedAction}`,
      responseData: { approvalId: pending.approvalId, action: pending.suggestedAction },
      shouldRespond: true,
      suggestedResponse: `Confirmed. Action "${pending.suggestedAction}" has been approved and will be processed.`,
      timestamp,
    };
  }

  /**
   * DENY — Reject a pending action.
   */
  private handleDeny(
    actionId: string,
    _intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const pending = this.approvalStore.approvals.find(
      (a) => a.from === message.from && a.status === "pending"
    );

    if (!pending) {
      return {
        actionId,
        intent: "deny",
        tier: 1,
        executed: true,
        status: "completed",
        summary: "No pending action to reject",
        responseData: { found: false },
        shouldRespond: true,
        suggestedResponse: "No pending actions to cancel. Reply HELP for available commands.",
        timestamp,
      };
    }

    pending.status = "rejected";
    pending.resolvedAt = timestamp;
    pending.resolvedBy = message.from;
    this.saveApprovals();

    return {
      actionId,
      intent: "deny",
      tier: 1,
      executed: true,
      status: "completed",
      summary: `Rejected pending action: ${pending.suggestedAction}`,
      responseData: { approvalId: pending.approvalId, action: pending.suggestedAction },
      shouldRespond: true,
      suggestedResponse: `Action "${pending.suggestedAction}" has been cancelled.`,
      timestamp,
    };
  }

  // ── Governance Handlers ────────────────────────────────────

  /**
   * Queue an action for human approval (Tier 2).
   */
  private queueForApproval(
    actionId: string,
    intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const approval: PendingApproval = {
      approvalId: crypto.randomBytes(8).toString("hex"),
      actionId,
      intent: intent.intent,
      tier: intent.tier,
      from: message.from,
      to: message.to,
      messageText: message.rawText,
      suggestedAction: intent.suggestedAction,
      entities: intent.entities as unknown as Record<string, unknown>,
      status: "pending",
      createdAt: timestamp,
      expiresAt: new Date(Date.now() + APPROVAL_TTL_HOURS * 60 * 60 * 1000).toISOString(),
    };

    this.approvalStore.approvals.push(approval);
    this.saveApprovals();

    // Notify operators about pending approval
    this.notifyOperator(approval, message.targetNumber);

    return {
      actionId,
      intent: intent.intent,
      tier: intent.tier,
      executed: false,
      status: "queued",
      summary: `Action queued for approval: ${intent.suggestedAction}`,
      responseData: {
        approvalId: approval.approvalId,
        action: intent.suggestedAction,
      },
      shouldRespond: true,
      suggestedResponse: "Your request has been received and is pending review. You will be notified once it is processed.",
      timestamp,
    };
  }

  /**
   * Escalate to human operator (Tier 3).
   */
  private escalate(
    actionId: string,
    intent: IntentResult,
    message: InboundMessage,
    timestamp: string
  ): ActionResult {
    const target = intent.escalationTarget || this.getDefaultEscalation(message.targetNumber);

    // Log escalation
    console.log(`[SCA] ESCALATION: ${message.from} → ${message.to} | Intent: ${intent.intent} | Target: ${target}`);
    console.log(`[SCA]   Message: ${message.rawText}`);

    return {
      actionId,
      intent: intent.intent,
      tier: intent.tier,
      executed: false,
      status: "escalated",
      summary: `Escalated to ${target}: ${intent.suggestedAction}`,
      responseData: {
        escalationTarget: target,
        intent: intent.intent,
      },
      shouldRespond: true,
      suggestedResponse: "Your message has been forwarded to our team. A representative will respond shortly.",
      escalationTarget: target,
      timestamp,
    };
  }

  // ── Helpers ────────────────────────────────────────────────

  /**
   * Summarize a signing session for SMS.
   */
  private summarizeSession(session: SigningSession): Record<string, unknown> {
    return {
      sessionId: session.sessionId,
      documentTitle: session.documentTitle,
      status: session.status,
      signerCount: session.signers.length,
      signatureCount: session.signatureCount,
      thresholdMet: session.thresholdMet,
      createdAt: session.createdAt,
      expiresAt: session.config.expiresAt,
    };
  }

  /**
   * Format a session status for SMS response.
   */
  private formatSessionStatus(session: SigningSession): string {
    const signed = session.signers.filter((s) => s.status === "signed").length;
    const total = session.signers.length;
    const lines = [
      `Document: "${session.documentTitle}"`,
      `Status: ${session.status.toUpperCase()}`,
      `Signatures: ${signed}/${total}`,
    ];
    if (session.config.expiresAt) {
      const exp = new Date(session.config.expiresAt);
      const now = new Date();
      const hoursLeft = Math.max(0, Math.round((exp.getTime() - now.getTime()) / (60 * 60 * 1000)));
      lines.push(`Expires in: ${hoursLeft}h`);
    }
    return lines.join("\n");
  }

  /**
   * Get contextual help text based on number mode.
   */
  private getHelp(mode: string): string {
    const modeHelp: Record<string, string> = {
      INFRA: "Commands:\n• STATUS — Check signing status\n• SIGN — Get your signing link\n• VERIFY — Verify a document\n• HELP — This message",
      ISSUER: "Commands:\n• STATUS — Deal status\n• DOCS — Request documents\n• SIGN — Sign documents\n• COMPLIANCE — Compliance inquiry\n• HELP — This message",
      VENUE: "Commands:\n• STATUS — Venue status\n• DOCS — Request package\n• HELP — This message",
      ONBOARDING: "Commands:\n• ONBOARD — Start onboarding\n• STATUS — Check application\n• DOCS — Request investor pack\n• HELP — This message",
      CUSTODY: "All custody requests are handled by our team. Your message will be forwarded.",
      DEAL: "Commands:\n• STATUS — Deal status\n• SIGN — Sign documents\n• DOCS — Request documents\n• HELP — This message",
    };
    return modeHelp[mode] || modeHelp["INFRA"];
  }

  /**
   * Get default escalation contact for a number.
   */
  private getDefaultEscalation(number: TelecomNumber | null): string {
    if (!number) return "ops@fthtrading.com";
    const rule = number.escalationRules.find((r) => r.trigger === "unknown-sender");
    return rule?.contact || "ops@fthtrading.com";
  }

  /**
   * Notify operator about a pending approval.
   */
  private notifyOperator(approval: PendingApproval, number: TelecomNumber | null): void {
    const target = this.getDefaultEscalation(number);
    console.log(`[SCA] APPROVAL REQUIRED: ${approval.approvalId}`);
    console.log(`[SCA]   From: ${approval.from}`);
    console.log(`[SCA]   Intent: ${approval.intent}`);
    console.log(`[SCA]   Action: ${approval.suggestedAction}`);
    console.log(`[SCA]   Notify: ${target}`);
  }

  // ── Approval Management ────────────────────────────────────

  /**
   * Get all pending approvals.
   */
  getPendingApprovals(): PendingApproval[] {
    this.expireStaleApprovals();
    return this.approvalStore.approvals.filter((a) => a.status === "pending");
  }

  /**
   * Approve a pending action.
   */
  approveAction(approvalId: string, approvedBy: string): PendingApproval | null {
    const approval = this.approvalStore.approvals.find(
      (a) => a.approvalId === approvalId && a.status === "pending"
    );
    if (!approval) return null;

    approval.status = "approved";
    approval.resolvedAt = new Date().toISOString();
    approval.resolvedBy = approvedBy;
    this.saveApprovals();
    return approval;
  }

  /**
   * Reject a pending action.
   */
  rejectAction(approvalId: string, rejectedBy: string): PendingApproval | null {
    const approval = this.approvalStore.approvals.find(
      (a) => a.approvalId === approvalId && a.status === "pending"
    );
    if (!approval) return null;

    approval.status = "rejected";
    approval.resolvedAt = new Date().toISOString();
    approval.resolvedBy = rejectedBy;
    this.saveApprovals();
    return approval;
  }

  /**
   * Expire stale approvals.
   */
  private expireStaleApprovals(): void {
    const now = new Date();
    for (const approval of this.approvalStore.approvals) {
      if (approval.status === "pending" && new Date(approval.expiresAt) < now) {
        approval.status = "expired";
        approval.resolvedAt = now.toISOString();
      }
    }
    this.saveApprovals();
  }

  /**
   * Get approval stats.
   */
  getApprovalStats(): { total: number; pending: number; approved: number; rejected: number; expired: number } {
    this.expireStaleApprovals();
    const approvals = this.approvalStore.approvals;
    return {
      total: approvals.length,
      pending: approvals.filter((a) => a.status === "pending").length,
      approved: approvals.filter((a) => a.status === "approved").length,
      rejected: approvals.filter((a) => a.status === "rejected").length,
      expired: approvals.filter((a) => a.status === "expired").length,
    };
  }

  // ── Persistence ────────────────────────────────────────────

  private loadApprovals(): ApprovalStore {
    if (fs.existsSync(this.approvalPath)) {
      try {
        return JSON.parse(fs.readFileSync(this.approvalPath, "utf-8"));
      } catch {
        // Corrupted file — start fresh
      }
    }
    return { engine: "sca-action-engine", version: "1.0.0", approvals: [] };
  }

  private saveApprovals(): void {
    fs.writeFileSync(this.approvalPath, JSON.stringify(this.approvalStore, null, 2));
  }
}

// ── Singleton ────────────────────────────────────────────────

let _engine: ActionEngine | null = null;

export function getActionEngine(): ActionEngine {
  if (!_engine) {
    _engine = new ActionEngine();
  }
  return _engine;
}
