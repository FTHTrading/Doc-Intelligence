// ─────────────────────────────────────────────────────────────
// Agreement State Engine — Active Contract Lifecycle Manager
//
// Contracts are not static documents. Once signed, they become
// active monitored objects with:
//   • Status lifecycle (Draft → Signed → Active → Completed)
//   • Obligation tracking
//   • Deadline management
//   • Payment trigger monitoring
//   • Amendment version control
//   • Escalation triggers
//
// Persistence: .doc-engine/agreement-states.json
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";
import {
  AgreementState,
  AgreementStatus,
  AgreementParty,
  Obligation,
  PaymentTrigger,
  Deadline,
  Amendment,
  StatusTransition,
  VALID_TRANSITIONS,
} from "../schema/researchSchema";

// ── Constants ────────────────────────────────────────────────

const AGREEMENT_STATE_FILE = "agreement-states.json";

interface AgreementStore {
  engine: string;
  version: string;
  createdAt: string;
  lastUpdated: string;
  agreements: AgreementState[];
}

// ── Agreement State Engine ───────────────────────────────────

export class AgreementStateEngine {
  private store: AgreementStore;
  private storePath: string;

  constructor(storeDir: string) {
    this.storePath = path.join(storeDir, AGREEMENT_STATE_FILE);
    this.store = this.load();
  }

  // ── Persistence ──────────────────────────────────────────

  private load(): AgreementStore {
    if (fs.existsSync(this.storePath)) {
      try {
        const raw = fs.readFileSync(this.storePath, "utf-8");
        return JSON.parse(raw);
      } catch {
        // Corrupted — start fresh
      }
    }
    return {
      engine: "Document Intelligence Engine — Agreement State Engine",
      version: "1.0.0",
      createdAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      agreements: [],
    };
  }

  private save(): void {
    this.store.lastUpdated = new Date().toISOString();
    const dir = path.dirname(this.storePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2), "utf-8");
  }

  // ── Create ─────────────────────────────────────────────────

  /**
   * Create a new agreement state from a document.
   */
  createAgreement(options: {
    title: string;
    sourceDocumentId: string;
    parties: AgreementParty[];
    sku?: string;
    cid?: string;
    governingLaw?: string;
    expirationDate?: string;
  }): AgreementState {
    const now = new Date().toISOString();
    const contentHash = crypto.createHash("sha256")
      .update(options.title + options.sourceDocumentId + now)
      .digest("hex");

    const agreementId = crypto.createHash("sha256")
      .update(contentHash + Math.random().toString())
      .digest("hex")
      .substring(0, 16);

    const agreement: AgreementState = {
      agreementId,
      title: options.title,
      status: "draft",
      parties: options.parties,
      sourceDocumentId: options.sourceDocumentId,
      sku: options.sku,
      cid: options.cid,
      obligations: [],
      paymentTriggers: [],
      deadlines: [],
      amendments: [],
      statusHistory: [{
        from: "draft" as AgreementStatus,
        to: "draft",
        timestamp: now,
        actor: "system",
        reason: "Agreement created",
      }],
      governingLaw: options.governingLaw,
      expirationDate: options.expirationDate,
      contentHash,
      createdAt: now,
      updatedAt: now,
    };

    this.store.agreements.push(agreement);
    this.save();
    return agreement;
  }

  // ── Status Transitions ────────────────────────────────────

  /**
   * Transition an agreement to a new status.
   * Validates the transition against VALID_TRANSITIONS map.
   */
  transitionStatus(
    agreementId: string,
    newStatus: AgreementStatus,
    actor: string,
    reason: string,
    evidence?: string
  ): AgreementState | { error: string } {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return { error: `Agreement not found: ${agreementId}` };

    const allowed = VALID_TRANSITIONS[agreement.status];
    if (!allowed.includes(newStatus)) {
      return {
        error: `Invalid transition: ${agreement.status} → ${newStatus}. Allowed: ${allowed.join(", ")}`,
      };
    }

    const transition: StatusTransition = {
      from: agreement.status,
      to: newStatus,
      timestamp: new Date().toISOString(),
      actor,
      reason,
      evidence,
    };

    agreement.statusHistory.push(transition);
    agreement.status = newStatus;
    agreement.updatedAt = new Date().toISOString();

    // Auto-set execution date when transitioning to active
    if (newStatus === "active" && !agreement.executionDate) {
      agreement.executionDate = new Date().toISOString();
    }

    this.save();
    return agreement;
  }

  // ── Obligations ────────────────────────────────────────────

  /**
   * Add an obligation to an agreement.
   */
  addObligation(agreementId: string, obligation: Omit<Obligation, "obligationId">): Obligation | null {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return null;

    const ob: Obligation = {
      obligationId: crypto.createHash("sha256")
        .update(obligation.description + Date.now().toString())
        .digest("hex")
        .substring(0, 12),
      ...obligation,
    };

    agreement.obligations.push(ob);
    agreement.updatedAt = new Date().toISOString();
    this.save();
    return ob;
  }

  /**
   * Fulfill an obligation — marks it as completed.
   */
  fulfillObligation(agreementId: string, obligationId: string, evidence?: string): boolean {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return false;

    const ob = agreement.obligations.find((o) => o.obligationId === obligationId);
    if (!ob) return false;

    ob.status = "fulfilled";
    ob.completedAt = new Date().toISOString();
    if (evidence) ob.evidence = evidence;

    agreement.updatedAt = new Date().toISOString();
    this.save();
    return true;
  }

  /**
   * Get overdue obligations across all agreements.
   */
  getOverdueObligations(): { agreementId: string; obligation: Obligation }[] {
    const now = new Date().toISOString();
    const results: { agreementId: string; obligation: Obligation }[] = [];

    for (const agreement of this.store.agreements) {
      if (agreement.status === "completed" || agreement.status === "archived" || agreement.status === "terminated") continue;

      for (const ob of agreement.obligations) {
        if (ob.status === "pending" && ob.dueDate < now) {
          ob.status = "overdue";
          results.push({ agreementId: agreement.agreementId, obligation: ob });
        }
        if (ob.status === "overdue") {
          results.push({ agreementId: agreement.agreementId, obligation: ob });
        }
      }
    }

    if (results.length > 0) this.save();
    return results;
  }

  // ── Payment Triggers ───────────────────────────────────────

  /**
   * Add a payment trigger to an agreement.
   */
  addPaymentTrigger(agreementId: string, trigger: Omit<PaymentTrigger, "triggerId">): PaymentTrigger | null {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return null;

    const pt: PaymentTrigger = {
      triggerId: crypto.createHash("sha256")
        .update(trigger.description + Date.now().toString())
        .digest("hex")
        .substring(0, 12),
      ...trigger,
    };

    agreement.paymentTriggers.push(pt);
    agreement.updatedAt = new Date().toISOString();
    this.save();
    return pt;
  }

  /**
   * Mark a payment trigger as triggered.
   */
  triggerPayment(agreementId: string, triggerId: string): boolean {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return false;

    const trigger = agreement.paymentTriggers.find((t) => t.triggerId === triggerId);
    if (!trigger) return false;

    trigger.status = "triggered";
    agreement.updatedAt = new Date().toISOString();
    this.save();
    return true;
  }

  /**
   * Mark a payment as paid.
   */
  confirmPayment(agreementId: string, triggerId: string, referenceNumber: string): boolean {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return false;

    const trigger = agreement.paymentTriggers.find((t) => t.triggerId === triggerId);
    if (!trigger) return false;

    trigger.status = "paid";
    trigger.paidAt = new Date().toISOString();
    trigger.referenceNumber = referenceNumber;
    agreement.updatedAt = new Date().toISOString();
    this.save();
    return true;
  }

  // ── Deadlines ──────────────────────────────────────────────

  /**
   * Add a deadline to an agreement.
   */
  addDeadline(agreementId: string, deadline: Omit<Deadline, "deadlineId">): Deadline | null {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return null;

    const dl: Deadline = {
      deadlineId: crypto.createHash("sha256")
        .update(deadline.description + Date.now().toString())
        .digest("hex")
        .substring(0, 12),
      ...deadline,
    };

    agreement.deadlines.push(dl);
    agreement.updatedAt = new Date().toISOString();
    this.save();
    return dl;
  }

  /**
   * Check all deadlines and return upcoming/missed ones.
   */
  checkDeadlines(daysAhead: number = 7): {
    upcoming: { agreementId: string; deadline: Deadline }[];
    missed: { agreementId: string; deadline: Deadline }[];
  } {
    const now = new Date();
    const futureDate = new Date(now.getTime() + daysAhead * 24 * 60 * 60 * 1000);
    const upcoming: { agreementId: string; deadline: Deadline }[] = [];
    const missed: { agreementId: string; deadline: Deadline }[] = [];

    for (const agreement of this.store.agreements) {
      if (["completed", "archived", "terminated"].includes(agreement.status)) continue;

      for (const dl of agreement.deadlines) {
        const dlDate = new Date(dl.date);

        if (dl.status === "upcoming" && dlDate < now) {
          dl.status = "missed";
          missed.push({ agreementId: agreement.agreementId, deadline: dl });
        } else if (dl.status === "missed") {
          missed.push({ agreementId: agreement.agreementId, deadline: dl });
        } else if (dl.status === "upcoming" && dlDate <= futureDate) {
          upcoming.push({ agreementId: agreement.agreementId, deadline: dl });
        }
      }
    }

    if (missed.length > 0) this.save();
    return { upcoming, missed };
  }

  // ── Amendments ─────────────────────────────────────────────

  /**
   * Record an amendment to an agreement.
   */
  addAmendment(
    agreementId: string,
    description: string,
    approvedBy: string[],
    contentHash: string,
    cid?: string
  ): Amendment | null {
    const agreement = this.store.agreements.find((a) => a.agreementId === agreementId);
    if (!agreement) return null;

    const prevVersion = agreement.amendments.length > 0
      ? agreement.amendments[agreement.amendments.length - 1].version
      : "1.0";

    const nextVersion = (parseFloat(prevVersion) + 0.1).toFixed(1);

    const amendment: Amendment = {
      amendmentId: crypto.createHash("sha256")
        .update(description + Date.now().toString())
        .digest("hex")
        .substring(0, 12),
      version: nextVersion,
      description,
      effectiveDate: new Date().toISOString(),
      approvedBy,
      contentHash,
      cid,
      previousVersion: prevVersion,
    };

    agreement.amendments.push(amendment);
    agreement.contentHash = contentHash;
    agreement.updatedAt = new Date().toISOString();

    // Auto-transition to amended status if active
    if (agreement.status === "active") {
      this.transitionStatus(agreementId, "amended", approvedBy[0] || "system", `Amendment ${nextVersion}: ${description}`);
    }

    this.save();
    return amendment;
  }

  // ── Query ──────────────────────────────────────────────────

  /** Get an agreement by ID */
  getAgreement(agreementId: string): AgreementState | undefined {
    return this.store.agreements.find((a) => a.agreementId === agreementId);
  }

  /** Get all agreements */
  getAllAgreements(): AgreementState[] {
    return [...this.store.agreements];
  }

  /** Get agreements by status */
  getByStatus(status: AgreementStatus): AgreementState[] {
    return this.store.agreements.filter((a) => a.status === status);
  }

  /** Get agreements for a specific party */
  getByParty(partyName: string): AgreementState[] {
    return this.store.agreements.filter((a) =>
      a.parties.some((p) => p.name.toLowerCase() === partyName.toLowerCase())
    );
  }

  /** Get agreements by SKU */
  getBySKU(sku: string): AgreementState | undefined {
    return this.store.agreements.find((a) => a.sku === sku);
  }

  // ── Dashboard / Status Report ──────────────────────────────

  /**
   * Generate a status report for all active agreements.
   */
  generateStatusReport(): string {
    const lines: string[] = [];
    lines.push("══════════════════════════════════════════════════════════");
    lines.push("  AGREEMENT STATUS REPORT");
    lines.push(`  Generated: ${new Date().toISOString()}`);
    lines.push("══════════════════════════════════════════════════════════");
    lines.push("");

    const statusCounts: Record<string, number> = {};
    for (const a of this.store.agreements) {
      statusCounts[a.status] = (statusCounts[a.status] || 0) + 1;
    }

    lines.push("  STATUS SUMMARY:");
    for (const [status, count] of Object.entries(statusCounts)) {
      lines.push(`    ${status.toUpperCase().padEnd(20)} ${count}`);
    }
    lines.push("");

    // Active agreements detail
    const active = this.store.agreements.filter((a) =>
      !["archived", "completed", "terminated"].includes(a.status)
    );

    for (const a of active) {
      lines.push(`── ${a.title} ──────────────────────────────`);
      lines.push(`  ID: ${a.agreementId}`);
      lines.push(`  Status: ${a.status.toUpperCase()}`);
      if (a.sku) lines.push(`  SKU: ${a.sku}`);
      lines.push(`  Parties: ${a.parties.map((p) => `${p.name} (${p.role})`).join(", ")}`);

      const pendingObs = a.obligations.filter((o) => o.status === "pending" || o.status === "overdue");
      if (pendingObs.length > 0) {
        lines.push(`  Obligations (${pendingObs.length} pending):`);
        for (const ob of pendingObs) {
          lines.push(`    [${ob.status.toUpperCase()}] ${ob.description} — due: ${ob.dueDate} — assigned: ${ob.assignedTo}`);
        }
      }

      const pendingPayments = a.paymentTriggers.filter((p) => p.status !== "paid");
      if (pendingPayments.length > 0) {
        lines.push(`  Payments (${pendingPayments.length} outstanding):`);
        for (const pt of pendingPayments) {
          lines.push(`    [$${pt.amount} ${pt.currency}] ${pt.description} — status: ${pt.status}`);
        }
      }

      lines.push("");
    }

    // Deadline alerts
    const deadlineCheck = this.checkDeadlines(14);
    if (deadlineCheck.missed.length > 0) {
      lines.push("  ⚠ MISSED DEADLINES:");
      for (const { agreementId, deadline } of deadlineCheck.missed) {
        lines.push(`    [${agreementId.substring(0, 8)}] ${deadline.description} — was due: ${deadline.date}`);
      }
      lines.push("");
    }
    if (deadlineCheck.upcoming.length > 0) {
      lines.push("  UPCOMING DEADLINES (14 days):");
      for (const { agreementId, deadline } of deadlineCheck.upcoming) {
        lines.push(`    [${agreementId.substring(0, 8)}] ${deadline.description} — due: ${deadline.date}`);
      }
      lines.push("");
    }

    // Overdue obligations
    const overdue = this.getOverdueObligations();
    if (overdue.length > 0) {
      lines.push("  ⚠ OVERDUE OBLIGATIONS:");
      for (const { agreementId, obligation } of overdue) {
        lines.push(`    [${agreementId.substring(0, 8)}] ${obligation.description} — assigned: ${obligation.assignedTo}`);
      }
    }

    lines.push("");
    lines.push("══════════════════════════════════════════════════════════");
    return lines.join("\n");
  }

  // ── Statistics ─────────────────────────────────────────────

  getStats(): {
    total: number;
    byStatus: Record<string, number>;
    totalObligations: number;
    overdueObligations: number;
    totalPayments: number;
    pendingPayments: number;
    totalAmendments: number;
  } {
    const byStatus: Record<string, number> = {};
    let totalObligations = 0;
    let overdueObligations = 0;
    let totalPayments = 0;
    let pendingPayments = 0;
    let totalAmendments = 0;

    for (const a of this.store.agreements) {
      byStatus[a.status] = (byStatus[a.status] || 0) + 1;
      totalObligations += a.obligations.length;
      overdueObligations += a.obligations.filter((o) => o.status === "overdue").length;
      totalPayments += a.paymentTriggers.length;
      pendingPayments += a.paymentTriggers.filter((p) => p.status !== "paid").length;
      totalAmendments += a.amendments.length;
    }

    return {
      total: this.store.agreements.length,
      byStatus,
      totalObligations,
      overdueObligations,
      totalPayments,
      pendingPayments,
      totalAmendments,
    };
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: AgreementStateEngine | null = null;

export function getAgreementEngine(storeDir?: string): AgreementStateEngine {
  if (!_instance) {
    const dir = storeDir || path.join(process.cwd(), ".doc-engine");
    _instance = new AgreementStateEngine(dir);
  }
  return _instance;
}
