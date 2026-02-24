// ─────────────────────────────────────────────────────────────
// Sovereign Comms Agent — Telecom Registry
//
// Manages the 43+ Telnyx number inventory.
// Each number is assigned:
//
//   • Entity binding (FTH Trading / FTH Capital / Custody)
//   • Mode binding (INFRA / ISSUER / VENUE)
//   • Purpose (signing / onboarding / compliance / deal / ops)
//   • Deal binding (optional — maps number to active deal)
//   • AI persona (governs tone and behavior)
//   • Escalation rules (who gets alerted)
//   • Rate limits (per-number message caps)
//   • A2P compliance metadata
//
// Numbers are segmented:
//   Infrastructure Mode:      10 numbers
//   Issuer Mode:              10 numbers
//   Venue Mode:               5 numbers
//   Investor Onboarding:      5 numbers
//   Custody & Treasury:       5 numbers
//   Deal-Specific Rotational: 8 numbers
//
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";

// ── Types ────────────────────────────────────────────────────

/** Operational mode binding */
export type TelecomMode = "INFRA" | "ISSUER" | "VENUE" | "ONBOARDING" | "CUSTODY" | "DEAL";

/** Number purpose */
export type NumberPurpose =
  | "signing"
  | "onboarding"
  | "compliance"
  | "deal-routing"
  | "operations"
  | "status"
  | "otp"
  | "escalation"
  | "marketing"
  | "general";

/** Number status */
export type NumberStatus = "active" | "reserved" | "suspended" | "decommissioned";

/** AI persona assigned to the number */
export interface AIPersona {
  /** Persona name */
  name: string;
  /** Tone: formal | professional | friendly */
  tone: "formal" | "professional" | "friendly";
  /** Whether to identify as AI */
  identifyAsAI: boolean;
  /** Greeting template */
  greeting: string;
  /** Signature line */
  signature: string;
}

/** Escalation rule */
export interface EscalationRule {
  /** Condition that triggers escalation */
  trigger: "unknown-sender" | "keyword" | "high-value" | "compliance" | "error" | "timeout" | "opt-out";
  /** Where to escalate */
  target: "operator" | "compliance" | "legal" | "management";
  /** How to escalate */
  method: "sms" | "email" | "slack" | "internal";
  /** Escalation contact */
  contact: string;
  /** Priority */
  priority: "low" | "medium" | "high" | "critical";
}

/** Rate limiting configuration */
export interface RateLimits {
  /** Max outbound messages per hour */
  maxPerHour: number;
  /** Max outbound messages per day */
  maxPerDay: number;
  /** Cooldown between messages to same recipient (seconds) */
  recipientCooldown: number;
  /** Max OTP sends per session */
  maxOTPPerSession: number;
}

/** A2P compliance metadata */
export interface ComplianceMetadata {
  /** Brand registration ID */
  brandId: string;
  /** Campaign ID */
  campaignId: string;
  /** Use case description */
  useCase: string;
  /** Opt-in method */
  optInMethod: string;
  /** HELP keyword response */
  helpResponse: string;
  /** STOP keyword response */
  stopResponse: string;
  /** Terms URL */
  termsUrl: string;
  /** Privacy URL */
  privacyUrl: string;
}

/** Registered telecom number */
export interface TelecomNumber {
  /** Unique registry entry ID */
  registryId: string;
  /** E.164 phone number */
  number: string;
  /** Display label */
  label: string;
  /** Entity this number belongs to */
  entity: string;
  /** Operational mode */
  mode: TelecomMode;
  /** Primary purpose */
  purpose: NumberPurpose;
  /** Deal binding (if deal-specific) */
  dealId: string | null;
  /** Deal name (human readable) */
  dealName: string | null;
  /** Status */
  status: NumberStatus;
  /** AI persona */
  persona: AIPersona;
  /** Escalation rules */
  escalationRules: EscalationRule[];
  /** Rate limits */
  rateLimits: RateLimits;
  /** A2P compliance */
  compliance: ComplianceMetadata;
  /** Telnyx-specific config */
  telnyxConfig: {
    /** Telnyx messaging profile ID */
    messagingProfileId: string;
    /** Telnyx connection ID */
    connectionId: string;
    /** Webhook URL for this number */
    webhookUrl: string;
  };
  /** Keywords this number responds to */
  keywords: string[];
  /** Allowed inbound senders (empty = all) */
  allowedSenders: string[];
  /** Blocked senders */
  blockedSenders: string[];
  /** Message counters */
  counters: {
    totalSent: number;
    totalReceived: number;
    todaySent: number;
    todayReceived: number;
    lastResetDate: string;
  };
  /** Created at */
  createdAt: string;
  /** Last activity */
  lastActivityAt: string | null;
}

/** Number assignment request */
export interface NumberAssignment {
  number: string;
  label: string;
  entity: string;
  mode: TelecomMode;
  purpose: NumberPurpose;
  dealId?: string;
  dealName?: string;
  persona?: Partial<AIPersona>;
  keywords?: string[];
  escalationRules?: EscalationRule[];
  rateLimits?: Partial<RateLimits>;
  compliance?: Partial<ComplianceMetadata>;
  telnyxConfig?: Partial<TelecomNumber["telnyxConfig"]>;
}

// ── Default Configurations ────────────────────────────────────

const DEFAULT_PERSONA: AIPersona = {
  name: "FTH Comms",
  tone: "professional",
  identifyAsAI: false,
  greeting: "FTH Trading — How can we assist?",
  signature: "— FTH Trading",
};

const MODE_PERSONAS: Record<TelecomMode, Partial<AIPersona>> = {
  INFRA: {
    name: "FTH Infrastructure",
    greeting: "FTH Infrastructure Operations — How can we help?",
    signature: "— FTH Infrastructure",
  },
  ISSUER: {
    name: "FTH Issuer Services",
    greeting: "FTH Trading — Issuer Services. How can we assist?",
    signature: "— FTH Issuer Services",
  },
  VENUE: {
    name: "FTH Venue Operations",
    greeting: "FTH Trading Venue — How can we assist?",
    signature: "— FTH Venue Operations",
  },
  ONBOARDING: {
    name: "FTH Onboarding",
    tone: "friendly",
    greeting: "Welcome to FTH Trading. Let's get you started.",
    signature: "— FTH Onboarding Team",
  },
  CUSTODY: {
    name: "FTH Custody",
    tone: "formal",
    greeting: "FTH Custody & Treasury — Secure Communications.",
    signature: "— FTH Custody & Treasury",
  },
  DEAL: {
    name: "FTH Deal Desk",
    greeting: "FTH Trading — Deal Operations.",
    signature: "— FTH Deal Desk",
  },
};

const DEFAULT_RATE_LIMITS: RateLimits = {
  maxPerHour: 60,
  maxPerDay: 500,
  recipientCooldown: 30,
  maxOTPPerSession: 5,
};

const DEFAULT_COMPLIANCE: ComplianceMetadata = {
  brandId: "FTH-TRADING-001",
  campaignId: "",
  useCase: "Institutional financial communications — signing, settlement, compliance",
  optInMethod: "Written consent during investor onboarding",
  helpResponse: "FTH Trading Support. For assistance, email support@fthtrading.com or call +1-877-570-9775.",
  stopResponse: "You have been unsubscribed from FTH Trading messages. Reply START to re-subscribe.",
  termsUrl: "https://fthtrading.com/terms",
  privacyUrl: "https://fthtrading.com/privacy",
};

const DEFAULT_ESCALATION: EscalationRule[] = [
  {
    trigger: "unknown-sender",
    target: "operator",
    method: "internal",
    contact: "ops@fthtrading.com",
    priority: "medium",
  },
  {
    trigger: "opt-out",
    target: "compliance",
    method: "email",
    contact: "compliance@fthtrading.com",
    priority: "high",
  },
  {
    trigger: "error",
    target: "operator",
    method: "internal",
    contact: "ops@fthtrading.com",
    priority: "high",
  },
];

// ── Store ────────────────────────────────────────────────────

interface RegistryStore {
  engine: string;
  version: string;
  numbers: TelecomNumber[];
  optOutList: string[]; // E.164 numbers that have opted out
  lastUpdated: string;
}

const STORE_DIR = path.join(process.cwd(), ".doc-engine");
const STORE_PATH = path.join(STORE_DIR, "sca-telecom-registry.json");

function loadStore(): RegistryStore {
  if (fs.existsSync(STORE_PATH)) {
    return JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
  }
  return {
    engine: "sca-telecom-registry",
    version: "1.0.0",
    numbers: [],
    optOutList: [],
    lastUpdated: new Date().toISOString(),
  };
}

function saveStore(store: RegistryStore): void {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  store.lastUpdated = new Date().toISOString();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), "utf-8");
}

// ── Telecom Registry ─────────────────────────────────────────

export class TelecomRegistry {
  private store: RegistryStore;

  constructor() {
    this.store = loadStore();
  }

  /**
   * Register a number in the inventory.
   */
  register(assignment: NumberAssignment): TelecomNumber {
    // Check for duplicate
    const existing = this.store.numbers.find((n) => n.number === assignment.number);
    if (existing) {
      throw new Error(`Number ${assignment.number} already registered as ${existing.label}`);
    }

    const registryId = crypto.randomBytes(16).toString("hex");
    const modePersona = MODE_PERSONAS[assignment.mode] || {};

    const entry: TelecomNumber = {
      registryId,
      number: assignment.number,
      label: assignment.label,
      entity: assignment.entity,
      mode: assignment.mode,
      purpose: assignment.purpose,
      dealId: assignment.dealId || null,
      dealName: assignment.dealName || null,
      status: "active",
      persona: {
        ...DEFAULT_PERSONA,
        ...modePersona,
        ...assignment.persona,
      },
      escalationRules: assignment.escalationRules || [...DEFAULT_ESCALATION],
      rateLimits: {
        ...DEFAULT_RATE_LIMITS,
        ...assignment.rateLimits,
      },
      compliance: {
        ...DEFAULT_COMPLIANCE,
        ...assignment.compliance,
      },
      telnyxConfig: {
        messagingProfileId: "",
        connectionId: "",
        webhookUrl: "",
        ...assignment.telnyxConfig,
      },
      keywords: assignment.keywords || [],
      allowedSenders: [],
      blockedSenders: [],
      counters: {
        totalSent: 0,
        totalReceived: 0,
        todaySent: 0,
        todayReceived: 0,
        lastResetDate: new Date().toISOString().split("T")[0],
      },
      createdAt: new Date().toISOString(),
      lastActivityAt: null,
    };

    this.store.numbers.push(entry);
    saveStore(this.store);
    return entry;
  }

  /**
   * Look up a number by E.164.
   */
  lookupNumber(number: string): TelecomNumber | null {
    return this.store.numbers.find((n) => n.number === number) || null;
  }

  /**
   * Look up by registry ID.
   */
  lookupById(registryId: string): TelecomNumber | null {
    return this.store.numbers.find((n) => n.registryId === registryId) || null;
  }

  /**
   * Get all numbers for a mode.
   */
  getByMode(mode: TelecomMode): TelecomNumber[] {
    return this.store.numbers.filter((n) => n.mode === mode && n.status === "active");
  }

  /**
   * Get all numbers for an entity.
   */
  getByEntity(entity: string): TelecomNumber[] {
    return this.store.numbers.filter((n) => n.entity === entity && n.status === "active");
  }

  /**
   * Get all numbers for a purpose.
   */
  getByPurpose(purpose: NumberPurpose): TelecomNumber[] {
    return this.store.numbers.filter((n) => n.purpose === purpose && n.status === "active");
  }

  /**
   * Get number bound to a specific deal.
   */
  getByDeal(dealId: string): TelecomNumber | null {
    return this.store.numbers.find((n) => n.dealId === dealId && n.status === "active") || null;
  }

  /**
   * Bind a number to a deal.
   */
  bindDeal(number: string, dealId: string, dealName: string): void {
    const entry = this.lookupNumber(number);
    if (!entry) throw new Error(`Number ${number} not registered`);
    entry.dealId = dealId;
    entry.dealName = dealName;
    saveStore(this.store);
  }

  /**
   * Unbind a number from a deal.
   */
  unbindDeal(number: string): void {
    const entry = this.lookupNumber(number);
    if (!entry) throw new Error(`Number ${number} not registered`);
    entry.dealId = null;
    entry.dealName = null;
    saveStore(this.store);
  }

  /**
   * Suspend a number.
   */
  suspend(number: string): void {
    const entry = this.lookupNumber(number);
    if (!entry) throw new Error(`Number ${number} not registered`);
    entry.status = "suspended";
    saveStore(this.store);
  }

  /**
   * Reactivate a number.
   */
  reactivate(number: string): void {
    const entry = this.lookupNumber(number);
    if (!entry) throw new Error(`Number ${number} not registered`);
    entry.status = "active";
    saveStore(this.store);
  }

  /**
   * Increment sent counter and check rate limits.
   * Returns true if send is allowed, false if rate-limited.
   */
  checkAndIncrementSend(number: string): { allowed: boolean; reason?: string } {
    const entry = this.lookupNumber(number);
    if (!entry) return { allowed: false, reason: "Number not registered" };
    if (entry.status !== "active") return { allowed: false, reason: `Number is ${entry.status}` };

    // Reset daily counters if needed
    const today = new Date().toISOString().split("T")[0];
    if (entry.counters.lastResetDate !== today) {
      entry.counters.todaySent = 0;
      entry.counters.todayReceived = 0;
      entry.counters.lastResetDate = today;
    }

    if (entry.counters.todaySent >= entry.rateLimits.maxPerDay) {
      return { allowed: false, reason: `Daily limit reached (${entry.rateLimits.maxPerDay})` };
    }

    entry.counters.todaySent++;
    entry.counters.totalSent++;
    entry.lastActivityAt = new Date().toISOString();
    saveStore(this.store);
    return { allowed: true };
  }

  /**
   * Increment received counter.
   */
  recordInbound(number: string): void {
    const entry = this.lookupNumber(number);
    if (!entry) return;

    const today = new Date().toISOString().split("T")[0];
    if (entry.counters.lastResetDate !== today) {
      entry.counters.todaySent = 0;
      entry.counters.todayReceived = 0;
      entry.counters.lastResetDate = today;
    }

    entry.counters.todayReceived++;
    entry.counters.totalReceived++;
    entry.lastActivityAt = new Date().toISOString();
    saveStore(this.store);
  }

  /**
   * Check if a sender has opted out.
   */
  isOptedOut(senderNumber: string): boolean {
    return this.store.optOutList.includes(senderNumber);
  }

  /**
   * Record an opt-out.
   */
  recordOptOut(senderNumber: string): void {
    if (!this.store.optOutList.includes(senderNumber)) {
      this.store.optOutList.push(senderNumber);
      saveStore(this.store);
    }
  }

  /**
   * Record an opt-in (re-subscribe).
   */
  recordOptIn(senderNumber: string): void {
    this.store.optOutList = this.store.optOutList.filter((n) => n !== senderNumber);
    saveStore(this.store);
  }

  /**
   * Check if sender is blocked on this number.
   */
  isBlocked(number: string, senderNumber: string): boolean {
    const entry = this.lookupNumber(number);
    if (!entry) return true;
    if (entry.blockedSenders.includes(senderNumber)) return true;
    if (entry.allowedSenders.length > 0 && !entry.allowedSenders.includes(senderNumber)) return true;
    return false;
  }

  /**
   * Get all active numbers.
   */
  getAllActive(): TelecomNumber[] {
    return this.store.numbers.filter((n) => n.status === "active");
  }

  /**
   * Get statistics.
   */
  getStats(): {
    total: number;
    active: number;
    suspended: number;
    byMode: Record<string, number>;
    byPurpose: Record<string, number>;
    byEntity: Record<string, number>;
    totalSent: number;
    totalReceived: number;
    optOuts: number;
  } {
    const byMode: Record<string, number> = {};
    const byPurpose: Record<string, number> = {};
    const byEntity: Record<string, number> = {};
    let active = 0, suspended = 0, totalSent = 0, totalReceived = 0;

    for (const n of this.store.numbers) {
      if (n.status === "active") active++;
      if (n.status === "suspended") suspended++;
      byMode[n.mode] = (byMode[n.mode] || 0) + 1;
      byPurpose[n.purpose] = (byPurpose[n.purpose] || 0) + 1;
      byEntity[n.entity] = (byEntity[n.entity] || 0) + 1;
      totalSent += n.counters.totalSent;
      totalReceived += n.counters.totalReceived;
    }

    return {
      total: this.store.numbers.length,
      active,
      suspended,
      byMode,
      byPurpose,
      byEntity,
      totalSent,
      totalReceived,
      optOuts: this.store.optOutList.length,
    };
  }

  /**
   * Format registry summary.
   */
  formatSummary(): string {
    const stats = this.getStats();
    const lines: string[] = [];
    lines.push("═══════════════════════════════════════════════════════");
    lines.push("  SOVEREIGN COMMS AGENT — TELECOM REGISTRY");
    lines.push("═══════════════════════════════════════════════════════");
    lines.push("");
    lines.push(`  Total numbers: ${stats.total}`);
    lines.push(`  Active: ${stats.active} | Suspended: ${stats.suspended}`);
    lines.push(`  Opt-outs: ${stats.optOuts}`);
    lines.push(`  Total sent: ${stats.totalSent} | Total received: ${stats.totalReceived}`);
    lines.push("");
    lines.push("  ── By Mode ──");
    for (const [mode, count] of Object.entries(stats.byMode)) {
      lines.push(`    ${mode}: ${count}`);
    }
    lines.push("");
    lines.push("  ── By Purpose ──");
    for (const [purpose, count] of Object.entries(stats.byPurpose)) {
      lines.push(`    ${purpose}: ${count}`);
    }
    lines.push("");
    lines.push("  ── Numbers ──");
    for (const n of this.store.numbers) {
      const deal = n.dealId ? ` → ${n.dealName || n.dealId}` : "";
      const status = n.status === "active" ? "✓" : "✗";
      lines.push(`    ${status} ${n.number}  ${n.label}  [${n.mode}/${n.purpose}]${deal}`);
    }
    lines.push("");
    return lines.join("\n");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _registry: TelecomRegistry | null = null;

export function getTelecomRegistry(): TelecomRegistry {
  if (!_registry) {
    _registry = new TelecomRegistry();
  }
  return _registry;
}
