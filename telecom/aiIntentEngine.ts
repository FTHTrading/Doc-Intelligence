// ─────────────────────────────────────────────────────────────
// Sovereign Comms Agent — AI Intent Engine
//
// Determines what a sender wants from their message.
// This is NOT an LLM — it's a deterministic rules-first
// engine with fuzzy matching fallback.
//
// Governance Model: Hybrid with Escalation Tiers
//
//   Tier 0 (Auto):     STATUS, HELP, STOP — no human needed
//   Tier 1 (AI-Act):   SIGN, DOCS, OTP, VERIFY — AI acts, logs
//   Tier 2 (Approve):  ONBOARD, FUND, COMPLIANCE — AI prepares, human approves
//   Tier 3 (Human):    Unknown, escalation, custody — routed to operator
//
// Intent classification is keyword-first, then pattern match,
// then context-aware fallback. No probabilistic guessing.
//
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import { InboundMessage } from "./inboundRouter";
import { TelecomNumber } from "./telecomRegistry";

// ── Types ────────────────────────────────────────────────────

/** Classified intent categories */
export type IntentCategory =
  | "sign"             // Request to sign a document
  | "status"           // Check session/deal status
  | "help"             // Request assistance
  | "otp"              // OTP verification code
  | "verify"           // Verify a document or signature
  | "onboard"          // Investor onboarding
  | "documents"        // Request document package
  | "fund"             // Funding-related
  | "compliance"       // Compliance inquiry
  | "custody"          // Custody operations
  | "escalate"         // Needs human attention
  | "confirm"          // Yes / confirm / approve
  | "deny"             // No / reject / decline
  | "unknown";         // Cannot classify

/** Governance tier */
export type GovernanceTier = 0 | 1 | 2 | 3;

/** Intent classification result */
export interface IntentResult {
  /** Unique classification ID */
  classificationId: string;
  /** Classified intent */
  intent: IntentCategory;
  /** Governance tier */
  tier: GovernanceTier;
  /** Confidence: high (keyword match), medium (pattern), low (fallback) */
  confidence: "high" | "medium" | "low";
  /** How the classification was made */
  method: "keyword" | "pattern" | "context" | "number-purpose" | "fallback";
  /** Extracted entities from the message */
  entities: ExtractedEntities;
  /** Whether this requires human approval before action */
  requiresApproval: boolean;
  /** Whether action can be taken automatically */
  autoExecute: boolean;
  /** Suggested action description */
  suggestedAction: string;
  /** Escalation target (if tier 3) */
  escalationTarget?: string;
}

/** Entities extracted from the message */
export interface ExtractedEntities {
  /** Session ID mentioned */
  sessionId: string | null;
  /** Deal ID mentioned */
  dealId: string | null;
  /** Document title mentioned */
  documentTitle: string | null;
  /** Signer name mentioned */
  signerName: string | null;
  /** Email mentioned */
  email: string | null;
  /** OTP code (6-digit) */
  otpCode: string | null;
  /** Reference number */
  referenceNumber: string | null;
  /** Amount mentioned */
  amount: string | null;
  /** Date mentioned */
  date: string | null;
}

// ── Intent Rules ─────────────────────────────────────────────

interface IntentRule {
  intent: IntentCategory;
  tier: GovernanceTier;
  keywords: string[];
  patterns: RegExp[];
  autoExecute: boolean;
  action: string;
}

const INTENT_RULES: IntentRule[] = [
  // ── Tier 0: Fully autonomous ──
  {
    intent: "status",
    tier: 0,
    keywords: ["STATUS", "CHECK", "PROGRESS", "UPDATE", "WHERE", "TRACK"],
    patterns: [
      /^STATUS\b/i,
      /\bcheck\s+(status|progress)\b/i,
      /\bhow\s+(is|are)\b.*\b(deal|session|document|signing)\b/i,
      /\bwhere\s+(is|are)\b/i,
      /\btrack(ing)?\b/i,
    ],
    autoExecute: true,
    action: "Query session/deal status and reply",
  },
  {
    intent: "help",
    tier: 0,
    keywords: ["HELP", "INFO", "SUPPORT", "CONTACT", "?"],
    patterns: [
      /^HELP\b/i,
      /\bneed\s+help\b/i,
      /\bhow\s+do\s+i\b/i,
      /\bwhat\s+(can|do)\b/i,
    ],
    autoExecute: true,
    action: "Send help information",
  },

  // ── Tier 1: AI acts, logged ──
  {
    intent: "sign",
    tier: 1,
    keywords: ["SIGN", "SIGNATURE", "EXECUTE", "COUNTERSIGN"],
    patterns: [
      /^SIGN\b/i,
      /\bsign(ing)?\s+(link|document|agreement|contract)\b/i,
      /\bready\s+to\s+sign\b/i,
      /\bsend\s+me\s+(the\s+)?(signing\s+)?link\b/i,
      /\bexecute\b/i,
      /\bcountersign\b/i,
    ],
    autoExecute: true,
    action: "Find or create signing session, generate link, send to signer",
  },
  {
    intent: "otp",
    tier: 1,
    keywords: [],
    patterns: [
      /^\d{6}$/,  // Exactly 6 digits = OTP
      /^OTP\s*:?\s*\d{6}$/i,
      /^CODE\s*:?\s*\d{6}$/i,
      /^VERIFY\s+\d{6}$/i,
    ],
    autoExecute: true,
    action: "Verify OTP code and unlock signing",
  },
  {
    intent: "verify",
    tier: 1,
    keywords: ["VERIFY", "VALIDATE", "AUTHENTIC", "CHECK-DOC"],
    patterns: [
      /^VERIFY\b/i,
      /\bverify\s+(document|signature|hash|cert)\b/i,
      /\bvalidate\b/i,
      /\bis\s+(this|it)\s+(real|authentic|valid)\b/i,
    ],
    autoExecute: true,
    action: "Verify document, signature, or hash",
  },
  {
    intent: "documents",
    tier: 1,
    keywords: ["DOCS", "DOCUMENTS", "INVESTOR-PACK", "PACK", "DOWNLOAD", "PDF"],
    patterns: [
      /^DOCS?\b/i,
      /\binvestor\s+(pack|docs|documents|package)\b/i,
      /\bsend\s+(me\s+)?(the\s+)?(docs?|documents?|pack(age)?)\b/i,
      /\bdownload\b/i,
      /\bget\s+(the\s+)?pdf\b/i,
    ],
    autoExecute: true,
    action: "Generate and send requested document package",
  },
  {
    intent: "confirm",
    tier: 1,
    keywords: ["YES", "CONFIRM", "APPROVE", "ACCEPT", "AGREED", "OK", "PROCEED"],
    patterns: [
      /^(YES|CONFIRM|APPROVE|ACCEPT|OK|Y|AGREED|PROCEED)\b/i,
      /\bi\s+(confirm|agree|accept|approve)\b/i,
    ],
    autoExecute: true,
    action: "Confirm pending action",
  },
  {
    intent: "deny",
    tier: 1,
    keywords: ["NO", "REJECT", "DECLINE", "REFUSE", "CANCEL", "ABORT"],
    patterns: [
      /^(NO|REJECT|DECLINE|N|REFUSE|CANCEL|ABORT)\b/i,
      /\bi\s+(reject|decline|refuse)\b/i,
    ],
    autoExecute: true,
    action: "Reject or cancel pending action",
  },

  // ── Tier 2: AI prepares, human approves ──
  {
    intent: "onboard",
    tier: 2,
    keywords: ["ONBOARD", "REGISTER", "JOIN", "APPLY", "KYC", "AML"],
    patterns: [
      /^ONBOARD\b/i,
      /\b(register|join|apply|participate)\b/i,
      /\bnew\s+(investor|client|counterparty)\b/i,
      /\bkyc\b/i,
      /\baml\b/i,
    ],
    autoExecute: false,
    action: "Initiate investor onboarding workflow (requires approval)",
  },
  {
    intent: "fund",
    tier: 2,
    keywords: ["FUND", "FUNDING", "PAYMENT", "SETTLE", "TRANSFER", "WIRE"],
    patterns: [
      /^FUND\b/i,
      /\bfunding\s+(status|update|confirm)\b/i,
      /\bpayment\b/i,
      /\bsettle(ment)?\b/i,
      /\bwire\s+transfer\b/i,
      /\bremittance\b/i,
    ],
    autoExecute: false,
    action: "Process funding inquiry (requires approval)",
  },
  {
    intent: "compliance",
    tier: 2,
    keywords: ["COMPLIANCE", "REGULATORY", "AUDIT", "REPORT", "FILING"],
    patterns: [
      /^COMPLIANCE\b/i,
      /\bcompliance\s+(status|report|question|filing)\b/i,
      /\bregulat(or|ory)\b/i,
      /\baudit\b/i,
      /\bfiling\b/i,
    ],
    autoExecute: false,
    action: "Route compliance inquiry (requires approval)",
  },

  // ── Tier 3: Human only ──
  {
    intent: "custody",
    tier: 3,
    keywords: ["CUSTODY", "VAULT", "COLLATERAL", "SAFEKEEPING", "TREASURY"],
    patterns: [
      /^CUSTODY\b/i,
      /\bcustody\b/i,
      /\bcollateral\b/i,
      /\bvault\b/i,
      /\bsafekeeping\b/i,
      /\btreasury\b/i,
    ],
    autoExecute: false,
    action: "Escalate to custody operations (human only)",
  },
];

// ── Entity Extraction ────────────────────────────────────────

function extractEntities(text: string): ExtractedEntities {
  return {
    sessionId: extractPattern(text, /\bsession[:\s-]*([a-f0-9]{8,32})\b/i),
    dealId: extractPattern(text, /\bdeal[:\s-]*([A-Z0-9-]+)\b/i) || extractPattern(text, /\bbond[:\s-]*(\d+)\b/i),
    documentTitle: extractPattern(text, /\bdoc(?:ument)?[:\s-]+["']?([^"'\n]+)["']?/i),
    signerName: null, // Would need NER — skip for deterministic engine
    email: extractPattern(text, /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/),
    otpCode: extractPattern(text, /\b(\d{6})\b/),
    referenceNumber: extractPattern(text, /\bref[:\s#-]*([A-Z0-9-]+)\b/i),
    amount: extractPattern(text, /\$[\d,]+\.?\d*/),
    date: extractPattern(text, /\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b/),
  };
}

function extractPattern(text: string, pattern: RegExp): string | null {
  const match = text.match(pattern);
  return match ? (match[1] || match[0]) : null;
}

// ── AI Intent Engine ─────────────────────────────────────────

export class AIIntentEngine {

  /**
   * Classify the intent of an inbound message.
   */
  classify(message: InboundMessage): IntentResult {
    const classificationId = crypto.randomBytes(8).toString("hex");
    const entities = extractEntities(message.rawText);

    // ── Phase 1: Exact keyword match (highest confidence) ──
    for (const rule of INTENT_RULES) {
      if (rule.keywords.includes(message.keyword)) {
        return this.buildResult(classificationId, rule, "high", "keyword", entities, message.targetNumber);
      }
    }

    // ── Phase 2: Pattern match ──
    for (const rule of INTENT_RULES) {
      for (const pattern of rule.patterns) {
        if (pattern.test(message.normalizedText) || pattern.test(message.rawText)) {
          return this.buildResult(classificationId, rule, "medium", "pattern", entities, message.targetNumber);
        }
      }
    }

    // ── Phase 3: Number purpose context ──
    // If the number has a specific purpose, use that as context
    if (message.targetNumber) {
      const purposeIntent = this.intentFromPurpose(message.targetNumber.purpose);
      if (purposeIntent) {
        const rule = INTENT_RULES.find((r) => r.intent === purposeIntent);
        if (rule) {
          return this.buildResult(classificationId, rule, "low", "number-purpose", entities, message.targetNumber);
        }
      }
    }

    // ── Phase 4: OTP detection (bare 6-digit number) ──
    if (/^\d{6}$/.test(message.normalizedText.trim())) {
      const otpRule = INTENT_RULES.find((r) => r.intent === "otp")!;
      entities.otpCode = message.normalizedText.trim();
      return this.buildResult(classificationId, otpRule, "high", "pattern", entities, message.targetNumber);
    }

    // ── Fallback: Unknown → Tier 3 escalation ──
    return {
      classificationId,
      intent: "unknown",
      tier: 3,
      confidence: "low",
      method: "fallback",
      entities,
      requiresApproval: true,
      autoExecute: false,
      suggestedAction: "Escalate to operator — unable to classify intent",
      escalationTarget: this.getEscalationTarget(message.targetNumber),
    };
  }

  /**
   * Build an IntentResult from a matched rule.
   */
  private buildResult(
    classificationId: string,
    rule: IntentRule,
    confidence: "high" | "medium" | "low",
    method: IntentResult["method"],
    entities: ExtractedEntities,
    targetNumber: TelecomNumber | null
  ): IntentResult {
    return {
      classificationId,
      intent: rule.intent,
      tier: rule.tier,
      confidence,
      method,
      entities,
      requiresApproval: rule.tier >= 2,
      autoExecute: rule.autoExecute,
      suggestedAction: rule.action,
      escalationTarget: rule.tier === 3 ? this.getEscalationTarget(targetNumber) : undefined,
    };
  }

  /**
   * Map number purpose to a default intent.
   */
  private intentFromPurpose(purpose: string): IntentCategory | null {
    const map: Record<string, IntentCategory> = {
      "signing": "sign",
      "onboarding": "onboard",
      "compliance": "compliance",
      "deal-routing": "status",
      "otp": "otp",
      "status": "status",
    };
    return map[purpose] || null;
  }

  /**
   * Get escalation target from number config.
   */
  private getEscalationTarget(targetNumber: TelecomNumber | null): string {
    if (!targetNumber) return "ops@fthtrading.com";
    const rule = targetNumber.escalationRules.find((r) => r.trigger === "unknown-sender");
    return rule?.contact || "ops@fthtrading.com";
  }

  /**
   * Get all supported intents with descriptions.
   */
  getIntentManifest(): Array<{ intent: IntentCategory; tier: GovernanceTier; keywords: string[]; action: string }> {
    return INTENT_RULES.map((r) => ({
      intent: r.intent,
      tier: r.tier,
      keywords: r.keywords,
      action: r.action,
    }));
  }
}

// ── Singleton ────────────────────────────────────────────────

let _engine: AIIntentEngine | null = null;

export function getAIIntentEngine(): AIIntentEngine {
  if (!_engine) {
    _engine = new AIIntentEngine();
  }
  return _engine;
}
