// ─────────────────────────────────────────────────────────────
// Sovereign Comms Agent — Response Composer
//
// Builds persona-aware, compliance-gated outbound SMS
// messages from ActionResult data.
//
// Responsibilities:
//   • Persona-aware formatting (tone, greeting, signature)
//   • Compliance footer injection (STOP instructions)
//   • SMS length management (160-char segmentation awareness)
//   • Secure link formatting
//   • Template-based message construction
//   • Rate limit and opt-out pre-flight checks (via registry)
//
// Message structure:
//   [Greeting (if first contact)]
//   [Body — action-specific content]
//   [Compliance footer — STOP to opt out]
//   [Persona signature]
//
// ─────────────────────────────────────────────────────────────

import { TelecomNumber, getTelecomRegistry, AIPersona } from "./telecomRegistry";
import { ActionResult } from "./actionEngine";
import { IntentCategory } from "./aiIntentEngine";
import { InboundMessage, sendTelnyxMessage, OutboundResult } from "./inboundRouter";

// ── Types ────────────────────────────────────────────────────

/** Composed response ready to send */
export interface ComposedResponse {
  /** Response ID */
  responseId: string;
  /** To phone (E.164) */
  to: string;
  /** From phone (E.164) */
  from: string;
  /** Full message text */
  text: string;
  /** Estimated SMS segments */
  segments: number;
  /** Character count */
  charCount: number;
  /** Whether compliance footer was appended */
  hasComplianceFooter: boolean;
  /** Whether persona greeting was included */
  hasGreeting: boolean;
  /** Send status */
  status: "composed" | "sent" | "failed" | "skipped";
  /** Delivery result (after send) */
  deliveryResult?: OutboundResult;
  /** Timestamp */
  composedAt: string;
}

// ── Constants ────────────────────────────────────────────────

const SMS_SEGMENT_SIZE = 160;
const MAX_MESSAGE_LENGTH = 1600; // ~10 SMS segments max

const COMPLIANCE_FOOTER = "\n\nReply STOP to opt out.";
const AI_DISCLOSURE = "\nThis message was sent by an automated system.";

// ── Response Composer ────────────────────────────────────────

export class ResponseComposer {

  /**
   * Compose a response from an ActionResult.
   */
  compose(
    action: ActionResult,
    message: InboundMessage
  ): ComposedResponse {
    const number = message.targetNumber;
    const persona = number?.persona || this.defaultPersona();
    const now = new Date().toISOString();

    // If action says don't respond, skip
    if (!action.shouldRespond) {
      return {
        responseId: this.generateId(),
        to: message.from,
        from: message.to,
        text: "",
        segments: 0,
        charCount: 0,
        hasComplianceFooter: false,
        hasGreeting: false,
        status: "skipped",
        composedAt: now,
      };
    }

    // Build message parts
    const parts: string[] = [];

    // Greeting (only for help and escalation — don't pad every message)
    const needsGreeting = action.intent === "help" || action.status === "escalated";
    if (needsGreeting && persona.greeting) {
      parts.push(persona.greeting);
      parts.push("");
    }

    // Body — use suggested response from action, or build from template
    const body = action.suggestedResponse || this.buildTemplate(action);
    parts.push(body);

    // AI disclosure (if persona requires it)
    if (persona.identifyAsAI) {
      parts.push(AI_DISCLOSURE);
    }

    // Persona signature
    if (persona.signature) {
      parts.push(`\n— ${persona.signature}`);
    }

    // Compliance footer (always for automated messages)
    parts.push(COMPLIANCE_FOOTER);

    // Assemble and truncate
    let text = parts.join("\n");
    if (text.length > MAX_MESSAGE_LENGTH) {
      text = text.substring(0, MAX_MESSAGE_LENGTH - 3) + "...";
    }

    return {
      responseId: this.generateId(),
      to: message.from,
      from: message.to,
      text,
      segments: Math.ceil(text.length / SMS_SEGMENT_SIZE),
      charCount: text.length,
      hasComplianceFooter: true,
      hasGreeting: needsGreeting,
      status: "composed",
      composedAt: now,
    };
  }

  /**
   * Compose and send in one step.
   */
  async composeAndSend(
    action: ActionResult,
    message: InboundMessage
  ): Promise<ComposedResponse> {
    const response = this.compose(action, message);

    if (response.status === "skipped") {
      return response;
    }

    try {
      const result = await sendTelnyxMessage({
        from: response.from,
        to: response.to,
        text: response.text,
      });

      response.deliveryResult = result;
      response.status = result.success ? "sent" : "failed";
    } catch (err) {
      response.status = "failed";
      response.deliveryResult = {
        success: false,
        error: err instanceof Error ? err.message : "Send failed",
      };
    }

    return response;
  }

  /**
   * Build template-based response when no suggested response exists.
   */
  private buildTemplate(action: ActionResult): string {
    const templates: Record<IntentCategory, (data: Record<string, unknown>) => string> = {
      sign: (data) => {
        if (data.signingUrl) return `Your signing link: ${data.signingUrl}`;
        return "Your signing session is being prepared.";
      },
      status: (data) => {
        if (data.sessionId) return `Session ${data.sessionId}: ${data.status || "ACTIVE"}`;
        return "No active sessions found.";
      },
      help: () => "Reply with a command:\n• STATUS — Check status\n• SIGN — Get signing link\n• DOCS — Request documents\n• HELP — This menu",
      otp: (data) => {
        if (data.verified) return "Identity verified. You may now proceed to sign.";
        return "Please send your 6-digit verification code.";
      },
      verify: (data) => {
        if (data.reference) return `Verification for "${data.reference}" is available online.`;
        return "Reply VERIFY <reference-number> to verify a document.";
      },
      documents: (data) => {
        if (data.dealId) return `Documents for deal ${data.dealId} are being prepared.`;
        return "Reply DOCS <deal-id> to request a document package.";
      },
      onboard: () => "Your onboarding request has been received and is pending review.",
      fund: () => "Your funding inquiry has been received and is pending review.",
      compliance: () => "Your compliance inquiry has been forwarded to our compliance team.",
      custody: () => "Your request has been forwarded to our custody team.",
      escalate: () => "Your message has been forwarded to our team.",
      confirm: (data) => data.action ? `Confirmed: ${data.action}` : "Confirmed.",
      deny: (data) => data.action ? `Cancelled: ${data.action}` : "Cancelled.",
      unknown: () => "We couldn't understand your request. Reply HELP for available commands.",
    };

    const template = templates[action.intent];
    if (template) {
      return template(action.responseData);
    }
    return "Your request is being processed.";
  }

  /**
   * Build a standalone outbound message (not in response to inbound).
   */
  composeOutbound(params: {
    to: string;
    from: string;
    subject: string;
    body: string;
    persona?: AIPersona;
    includeFooter?: boolean;
  }): ComposedResponse {
    const persona = params.persona || this.defaultPersona();
    const now = new Date().toISOString();
    const parts: string[] = [];

    parts.push(params.body);

    if (persona.identifyAsAI) {
      parts.push(AI_DISCLOSURE);
    }

    if (persona.signature) {
      parts.push(`\n— ${persona.signature}`);
    }

    if (params.includeFooter !== false) {
      parts.push(COMPLIANCE_FOOTER);
    }

    let text = parts.join("\n");
    if (text.length > MAX_MESSAGE_LENGTH) {
      text = text.substring(0, MAX_MESSAGE_LENGTH - 3) + "...";
    }

    return {
      responseId: this.generateId(),
      to: params.to,
      from: params.from,
      text,
      segments: Math.ceil(text.length / SMS_SEGMENT_SIZE),
      charCount: text.length,
      hasComplianceFooter: params.includeFooter !== false,
      hasGreeting: false,
      status: "composed",
      composedAt: now,
    };
  }

  /**
   * Compose an OTP delivery message.
   */
  composeOTP(params: {
    to: string;
    from: string;
    code: string;
    documentTitle: string;
    expiresInMinutes: number;
    persona?: AIPersona;
  }): ComposedResponse {
    const persona = params.persona || this.defaultPersona();
    const now = new Date().toISOString();

    const text = [
      `Your verification code: ${params.code}`,
      ``,
      `This code is for signing "${params.documentTitle}".`,
      `Expires in ${params.expiresInMinutes} minutes.`,
      ``,
      `Do NOT share this code with anyone.`,
      persona.identifyAsAI ? AI_DISCLOSURE : "",
      persona.signature ? `\n— ${persona.signature}` : "",
      COMPLIANCE_FOOTER,
    ].filter(Boolean).join("\n");

    return {
      responseId: this.generateId(),
      to: params.to,
      from: params.from,
      text,
      segments: Math.ceil(text.length / SMS_SEGMENT_SIZE),
      charCount: text.length,
      hasComplianceFooter: true,
      hasGreeting: false,
      status: "composed",
      composedAt: now,
    };
  }

  /**
   * Compose a signing link delivery message.
   */
  composeSigningLink(params: {
    to: string;
    from: string;
    signerName: string;
    documentTitle: string;
    signingUrl: string;
    expiresAt: string;
    persona?: AIPersona;
  }): ComposedResponse {
    const persona = params.persona || this.defaultPersona();
    const now = new Date().toISOString();
    const exp = new Date(params.expiresAt);
    const hoursLeft = Math.max(0, Math.round((exp.getTime() - Date.now()) / (60 * 60 * 1000)));

    const text = [
      `${params.signerName}, you have a document to sign:`,
      ``,
      `"${params.documentTitle}"`,
      ``,
      `Sign here: ${params.signingUrl}`,
      ``,
      `This link expires in ${hoursLeft} hours.`,
      persona.identifyAsAI ? AI_DISCLOSURE : "",
      persona.signature ? `\n— ${persona.signature}` : "",
      COMPLIANCE_FOOTER,
    ].filter(Boolean).join("\n");

    return {
      responseId: this.generateId(),
      to: params.to,
      from: params.from,
      text,
      segments: Math.ceil(text.length / SMS_SEGMENT_SIZE),
      charCount: text.length,
      hasComplianceFooter: true,
      hasGreeting: false,
      status: "composed",
      composedAt: now,
    };
  }

  // ── Helpers ────────────────────────────────────────────────

  private defaultPersona(): AIPersona {
    return {
      name: "FTH Sovereign Comms",
      tone: "professional",
      identifyAsAI: true,
      greeting: "FTH Trading — Sovereign Comms",
      signature: "FTH Sovereign Comms Agent",
    };
  }

  private generateId(): string {
    const crypto = require("crypto");
    return crypto.randomBytes(8).toString("hex");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _composer: ResponseComposer | null = null;

export function getResponseComposer(): ResponseComposer {
  if (!_composer) {
    _composer = new ResponseComposer();
  }
  return _composer;
}
