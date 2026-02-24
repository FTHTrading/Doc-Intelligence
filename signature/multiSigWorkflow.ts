// ─────────────────────────────────────────────────────────────
// Multi-Signature Workflow — Sovereign Multi-Party Signing
//
// Extends the SignatureEngine with:
//
//   1. Required signature threshold (--require-signatures N)
//   2. Counterparty designation (--counterparty email)
//   3. Pending state management
//   4. Partial signature tracking
//   5. Finalization threshold with automatic completion
//   6. Timestamp ordering validation
//   7. Cryptographic certificate export (JSON + summary)
//   8. Signature invitation / routing
//
// A document is not "signed" until the threshold is met.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";
import {
  SignerIdentity,
  DigitalSignature,
  SignatureState,
  SignatureType,
  SignatureStatus,
} from "./signatureEngine";

// ── Types ────────────────────────────────────────────────────

/** Multi-sig workflow status */
export type WorkflowStatus =
  | "draft"            // Workflow created, no signatures yet
  | "pending"          // Awaiting signatures
  | "partial"          // Some signatures collected, below threshold
  | "threshold-met"    // Required threshold met
  | "finalized"        // All required signatures obtained, locked
  | "expired"          // Deadline passed without completion
  | "rejected"         // A required signer rejected
  | "cancelled";       // Workflow cancelled by initiator

/** Counterparty designation */
export interface Counterparty {
  /** Counterparty email (unique identifier) */
  email: string;
  /** Display name */
  name: string;
  /** Organization */
  organization?: string;
  /** Required role for this counterparty */
  role: string;
  /** Required signature type */
  signatureType: SignatureType;
  /** Whether this counterparty is required (vs. optional witness) */
  required: boolean;
  /** Invitation sent at */
  invitedAt?: string;
  /** Signed at (if completed) */
  signedAt?: string;
  /** Signature hash (if signed) */
  signatureHash?: string;
  /** Rejected at (if rejected) */
  rejectedAt?: string;
  /** Rejection reason */
  rejectionReason?: string;
}

/** Multi-sig workflow configuration */
export interface MultiSigConfig {
  /** Minimum number of signatures required to finalize */
  requiredSignatures: number;
  /** List of designated counterparties */
  counterparties: Counterparty[];
  /** Require all counterparties (true) or just threshold (false) */
  requireAll: boolean;
  /** Deadline for signature collection (ISO timestamp, optional) */
  deadline?: string;
  /** Signature ordering: strict (must sign in order) or any (parallel) */
  ordering: "strict" | "any";
  /** Whether the initiator's signature counts toward threshold */
  initiatorCounts: boolean;
}

/** Multi-sig workflow record */
export interface MultiSigWorkflow {
  /** Workflow ID */
  workflowId: string;
  /** Associated document ID */
  documentId: string;
  /** Document SKU */
  sku?: string;
  /** Document hash at workflow creation */
  documentHash: string;
  /** Workflow configuration */
  config: MultiSigConfig;
  /** Current workflow status */
  status: WorkflowStatus;
  /** Initiator identity */
  initiator: SignerIdentity;
  /** Counterparties with their signing status */
  counterparties: Counterparty[];
  /** Collected signatures (by email) */
  signatures: Map<string, DigitalSignature> | Record<string, DigitalSignature>;
  /** Current signature count */
  signatureCount: number;
  /** Whether threshold is met */
  thresholdMet: boolean;
  /** Created at */
  createdAt: string;
  /** Last activity timestamp */
  lastActivityAt: string;
  /** Finalized at (if finalized) */
  finalizedAt?: string;
  /** Workflow hash (self-integrity) */
  workflowHash: string;
}

/** Signature action result */
export interface SignatureActionResult {
  success: boolean;
  action: "signed" | "rejected" | "error";
  workflowStatus: WorkflowStatus;
  signatureCount: number;
  threshold: number;
  thresholdMet: boolean;
  message: string;
}

/** Workflow certificate — exported proof of completed multi-sig */
export interface WorkflowCertificate {
  /** Certificate ID */
  certificateId: string;
  /** Workflow ID */
  workflowId: string;
  /** Document ID */
  documentId: string;
  /** Document SKU */
  sku?: string;
  /** Document hash */
  documentHash: string;
  /** All participating signers */
  signers: Array<{
    name: string;
    email: string;
    role: string;
    signatureType: SignatureType;
    signedAt: string;
    signatureHash: string;
  }>;
  /** Threshold required */
  threshold: number;
  /** Total signatures collected */
  totalSignatures: number;
  /** Finalized timestamp */
  finalizedAt: string;
  /** Certificate hash (SHA-256 of deterministic serialization) */
  certificateHash: string;
  /** Certificate creation timestamp */
  issuedAt: string;
}

// ── Multi-Sig Workflow Engine ────────────────────────────────

interface WorkflowStore {
  engine: string;
  version: string;
  workflows: Array<Omit<MultiSigWorkflow, "signatures"> & { signatures: Record<string, DigitalSignature> }>;
}

const WORKFLOW_FILE = "multisig-workflows.json";

export class MultiSigEngine {
  private store: WorkflowStore;
  private storePath: string;

  constructor(storeDir: string = ".doc-engine") {
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.storePath = path.join(storeDir, WORKFLOW_FILE);
    this.store = this.load();
  }

  // ── Workflow Creation ────────────────────────────────────

  /**
   * Create a new multi-sig workflow for a document.
   */
  createWorkflow(params: {
    documentId: string;
    documentHash: string;
    sku?: string;
    initiator: SignerIdentity;
    requiredSignatures: number;
    counterparties: Array<{
      email: string;
      name: string;
      organization?: string;
      role: string;
      signatureType: SignatureType;
      required: boolean;
    }>;
    ordering?: "strict" | "any";
    deadline?: string;
    initiatorCounts?: boolean;
  }): MultiSigWorkflow {
    const workflowId = crypto.randomBytes(16).toString("hex");
    const now = new Date().toISOString();

    // Validate threshold
    const totalPossible = params.counterparties.length + (params.initiatorCounts !== false ? 1 : 0);
    if (params.requiredSignatures > totalPossible) {
      throw new Error(
        `[MULTISIG] Required signatures (${params.requiredSignatures}) exceeds total possible signers (${totalPossible})`
      );
    }
    if (params.requiredSignatures < 1) {
      throw new Error("[MULTISIG] Required signatures must be at least 1");
    }

    const counterparties: Counterparty[] = params.counterparties.map(cp => ({
      ...cp,
      invitedAt: now,
    }));

    const config: MultiSigConfig = {
      requiredSignatures: params.requiredSignatures,
      counterparties,
      requireAll: params.requiredSignatures === totalPossible,
      deadline: params.deadline,
      ordering: params.ordering || "any",
      initiatorCounts: params.initiatorCounts !== false,
    };

    const workflow: MultiSigWorkflow = {
      workflowId,
      documentId: params.documentId,
      sku: params.sku,
      documentHash: params.documentHash,
      config,
      status: "draft",
      initiator: params.initiator,
      counterparties,
      signatures: {},
      signatureCount: 0,
      thresholdMet: false,
      createdAt: now,
      lastActivityAt: now,
      workflowHash: "",
    };

    workflow.workflowHash = this.computeWorkflowHash(workflow);

    this.store.workflows.push(workflow as any);
    this.save();

    console.log(`[MULTISIG] Workflow created: ${workflowId.substring(0, 12)}...`);
    console.log(`[MULTISIG] Threshold: ${params.requiredSignatures} of ${totalPossible}`);
    console.log(`[MULTISIG] Counterparties: ${counterparties.length}`);

    return workflow;
  }

  // ── Signature Collection ─────────────────────────────────

  /**
   * Record a signature from a counterparty or initiator.
   */
  addSignature(
    workflowId: string,
    signature: DigitalSignature
  ): SignatureActionResult {
    const workflow = this.findWorkflow(workflowId);
    if (!workflow) {
      return {
        success: false,
        action: "error",
        workflowStatus: "draft",
        signatureCount: 0,
        threshold: 0,
        thresholdMet: false,
        message: `Workflow not found: ${workflowId}`,
      };
    }

    // Check if workflow is in a signable state
    if (workflow.status === "finalized" || workflow.status === "cancelled" || workflow.status === "expired") {
      return {
        success: false,
        action: "error",
        workflowStatus: workflow.status,
        signatureCount: workflow.signatureCount,
        threshold: workflow.config.requiredSignatures,
        thresholdMet: workflow.thresholdMet,
        message: `Workflow is ${workflow.status} — no further signatures accepted`,
      };
    }

    // Check deadline
    if (workflow.config.deadline) {
      if (new Date() > new Date(workflow.config.deadline)) {
        workflow.status = "expired";
        this.save();
        return {
          success: false,
          action: "error",
          workflowStatus: "expired",
          signatureCount: workflow.signatureCount,
          threshold: workflow.config.requiredSignatures,
          thresholdMet: false,
          message: "Workflow deadline has passed",
        };
      }
    }

    const signerEmail = signature.signer.email;
    const sigs = workflow.signatures as Record<string, DigitalSignature>;

    // Check for duplicate signature
    if (sigs[signerEmail]) {
      return {
        success: false,
        action: "error",
        workflowStatus: workflow.status,
        signatureCount: workflow.signatureCount,
        threshold: workflow.config.requiredSignatures,
        thresholdMet: workflow.thresholdMet,
        message: `${signerEmail} has already signed this workflow`,
      };
    }

    // Check ordering (if strict)
    if (workflow.config.ordering === "strict") {
      const expectedNext = this.getNextRequiredSigner(workflow);
      if (expectedNext && expectedNext.email !== signerEmail) {
        return {
          success: false,
          action: "error",
          workflowStatus: workflow.status,
          signatureCount: workflow.signatureCount,
          threshold: workflow.config.requiredSignatures,
          thresholdMet: workflow.thresholdMet,
          message: `Strict ordering: expected ${expectedNext.email}, got ${signerEmail}`,
        };
      }
    }

    // Check timestamp ordering (must be after last activity)
    const sigTimestamp = new Date(signature.signedAt).getTime();
    const lastActivity = new Date(workflow.lastActivityAt).getTime();
    if (sigTimestamp < lastActivity) {
      return {
        success: false,
        action: "error",
        workflowStatus: workflow.status,
        signatureCount: workflow.signatureCount,
        threshold: workflow.config.requiredSignatures,
        thresholdMet: workflow.thresholdMet,
        message: `Timestamp regression: signature at ${signature.signedAt} is before last activity at ${workflow.lastActivityAt}`,
      };
    }

    // Record the signature
    sigs[signerEmail] = signature;
    workflow.signatureCount = Object.keys(sigs).length;
    workflow.lastActivityAt = signature.signedAt;

    // Update counterparty status
    const cp = workflow.counterparties.find(c => c.email === signerEmail);
    if (cp) {
      cp.signedAt = signature.signedAt;
      cp.signatureHash = signature.signatureHash;
    }

    // Check threshold
    workflow.thresholdMet = workflow.signatureCount >= workflow.config.requiredSignatures;

    // Update status
    if (workflow.thresholdMet) {
      const allRequired = workflow.counterparties
        .filter(c => c.required)
        .every(c => !!c.signedAt);

      if (workflow.config.requireAll && allRequired) {
        workflow.status = "finalized";
        workflow.finalizedAt = signature.signedAt;
      } else if (!workflow.config.requireAll) {
        workflow.status = "threshold-met";
      } else {
        workflow.status = "partial";
      }
    } else {
      workflow.status = workflow.signatureCount > 0 ? "partial" : "pending";
    }

    // Recompute workflow hash
    workflow.workflowHash = this.computeWorkflowHash(workflow);
    this.save();

    console.log(`[MULTISIG] Signature recorded: ${signerEmail} (${workflow.signatureCount}/${workflow.config.requiredSignatures})`);

    return {
      success: true,
      action: "signed",
      workflowStatus: workflow.status,
      signatureCount: workflow.signatureCount,
      threshold: workflow.config.requiredSignatures,
      thresholdMet: workflow.thresholdMet,
      message: workflow.thresholdMet
        ? `Threshold met! ${workflow.signatureCount}/${workflow.config.requiredSignatures} signatures collected.`
        : `${workflow.signatureCount}/${workflow.config.requiredSignatures} signatures collected. Awaiting more.`,
    };
  }

  /**
   * Record a rejection from a counterparty.
   */
  rejectSignature(
    workflowId: string,
    email: string,
    reason: string
  ): SignatureActionResult {
    const workflow = this.findWorkflow(workflowId);
    if (!workflow) {
      return {
        success: false,
        action: "error",
        workflowStatus: "draft",
        signatureCount: 0,
        threshold: 0,
        thresholdMet: false,
        message: `Workflow not found: ${workflowId}`,
      };
    }

    const cp = workflow.counterparties.find(c => c.email === email);
    if (!cp) {
      return {
        success: false,
        action: "error",
        workflowStatus: workflow.status,
        signatureCount: workflow.signatureCount,
        threshold: workflow.config.requiredSignatures,
        thresholdMet: workflow.thresholdMet,
        message: `Counterparty not found: ${email}`,
      };
    }

    cp.rejectedAt = new Date().toISOString();
    cp.rejectionReason = reason;

    // If a required signer rejects, the workflow fails
    if (cp.required) {
      workflow.status = "rejected";
    }

    workflow.lastActivityAt = cp.rejectedAt;
    workflow.workflowHash = this.computeWorkflowHash(workflow);
    this.save();

    console.log(`[MULTISIG] Signature rejected: ${email} — ${reason}`);

    return {
      success: true,
      action: "rejected",
      workflowStatus: workflow.status,
      signatureCount: workflow.signatureCount,
      threshold: workflow.config.requiredSignatures,
      thresholdMet: workflow.thresholdMet,
      message: cp.required
        ? `Required signer ${email} rejected. Workflow failed.`
        : `Optional signer ${email} rejected. Workflow continues.`,
    };
  }

  // ── Finalization ─────────────────────────────────────────

  /**
   * Finalize a workflow once threshold is met.
   * Only allowed if thresholdMet === true.
   */
  finalize(workflowId: string): MultiSigWorkflow | null {
    const workflow = this.findWorkflow(workflowId);
    if (!workflow) return null;

    if (!workflow.thresholdMet) {
      console.warn(`[MULTISIG] Cannot finalize — threshold not met (${workflow.signatureCount}/${workflow.config.requiredSignatures})`);
      return null;
    }

    if (workflow.status === "finalized") {
      console.warn("[MULTISIG] Workflow already finalized");
      return workflow;
    }

    workflow.status = "finalized";
    workflow.finalizedAt = new Date().toISOString();
    workflow.workflowHash = this.computeWorkflowHash(workflow);
    this.save();

    console.log(`[MULTISIG] Workflow finalized: ${workflowId.substring(0, 12)}...`);
    return workflow;
  }

  // ── Certificate Export ───────────────────────────────────

  /**
   * Export a cryptographic certificate proving multi-sig completion.
   */
  exportCertificate(workflowId: string): WorkflowCertificate | null {
    const workflow = this.findWorkflow(workflowId);
    if (!workflow || workflow.status !== "finalized") {
      console.warn("[MULTISIG] Certificate export requires finalized workflow");
      return null;
    }

    const certificateId = crypto.randomBytes(16).toString("hex");
    const sigs = workflow.signatures as Record<string, DigitalSignature>;

    const signers = Object.values(sigs).map(sig => ({
      name: sig.signer.name,
      email: sig.signer.email,
      role: sig.signer.role,
      signatureType: sig.signer.signatureType,
      signedAt: sig.signedAt,
      signatureHash: sig.signatureHash,
    }));

    // Sort signers by signing time for deterministic output
    signers.sort((a, b) => new Date(a.signedAt).getTime() - new Date(b.signedAt).getTime());

    const certBody = {
      certificateId,
      workflowId,
      documentId: workflow.documentId,
      sku: workflow.sku,
      documentHash: workflow.documentHash,
      signers,
      threshold: workflow.config.requiredSignatures,
      totalSignatures: workflow.signatureCount,
      finalizedAt: workflow.finalizedAt || new Date().toISOString(),
    };

    // Deterministic hash of certificate
    const hashInput = JSON.stringify({
      documentId: certBody.documentId,
      documentHash: certBody.documentHash,
      signers: certBody.signers.map(s => `${s.email}:${s.signatureHash}:${s.signedAt}`),
      threshold: certBody.threshold,
      finalizedAt: certBody.finalizedAt,
    });

    const certificateHash = crypto.createHash("sha256").update(hashInput).digest("hex");

    return {
      ...certBody,
      certificateHash,
      issuedAt: new Date().toISOString(),
    };
  }

  /**
   * Export certificate as formatted text report.
   */
  exportCertificateReport(workflowId: string): string | null {
    const cert = this.exportCertificate(workflowId);
    if (!cert) return null;

    const lines: string[] = [];
    lines.push(`╔══════════════════════════════════════════════════════╗`);
    lines.push(`║  MULTI-SIGNATURE CERTIFICATE                        ║`);
    lines.push(`╚══════════════════════════════════════════════════════╝`);
    lines.push(``);
    lines.push(`  Certificate ID:  ${cert.certificateId}`);
    lines.push(`  Document ID:     ${cert.documentId.substring(0, 20)}...`);
    if (cert.sku) lines.push(`  Document SKU:    ${cert.sku}`);
    lines.push(`  Document Hash:   ${cert.documentHash.substring(0, 32)}...`);
    lines.push(``);
    lines.push(`  ─── Threshold ────────────────────────────────────`);
    lines.push(`  Required: ${cert.threshold} | Collected: ${cert.totalSignatures}`);
    lines.push(`  Status: FINALIZED`);
    lines.push(`  Finalized: ${cert.finalizedAt}`);
    lines.push(``);
    lines.push(`  ─── Signatories (${cert.signers.length}) ──────────────────────`);
    for (const s of cert.signers) {
      lines.push(`  [${s.signatureType.toUpperCase()}] ${s.name} <${s.email}>`);
      lines.push(`    Role: ${s.role}`);
      lines.push(`    Signed: ${s.signedAt}`);
      lines.push(`    Hash: ${s.signatureHash.substring(0, 32)}...`);
      lines.push(``);
    }
    lines.push(`  ─── Integrity ────────────────────────────────────`);
    lines.push(`  Certificate Hash: ${cert.certificateHash}`);
    lines.push(`  Issued: ${cert.issuedAt}`);
    lines.push(``);

    return lines.join("\n");
  }

  // ── Query ────────────────────────────────────────────────

  /**
   * Get a workflow by ID.
   */
  getWorkflow(workflowId: string): MultiSigWorkflow | undefined {
    return this.findWorkflow(workflowId);
  }

  /**
   * Get workflow for a document.
   */
  getWorkflowByDocument(documentId: string): MultiSigWorkflow | undefined {
    return this.store.workflows.find(w => w.documentId === documentId) as MultiSigWorkflow | undefined;
  }

  /**
   * Get all workflows awaiting a specific email's signature.
   */
  getPendingForSigner(email: string): MultiSigWorkflow[] {
    return this.store.workflows.filter(w => {
      if (w.status === "finalized" || w.status === "cancelled" || w.status === "expired" || w.status === "rejected") {
        return false;
      }
      const cp = w.counterparties.find(c => c.email === email);
      if (!cp) return false;
      return !cp.signedAt && !cp.rejectedAt;
    }) as MultiSigWorkflow[];
  }

  /**
   * Get all active (non-finalized) workflows.
   */
  getActiveWorkflows(): MultiSigWorkflow[] {
    return this.store.workflows.filter(w =>
      w.status !== "finalized" && w.status !== "cancelled" && w.status !== "expired"
    ) as MultiSigWorkflow[];
  }

  /**
   * Get workflow statistics.
   */
  getStats(): {
    totalWorkflows: number;
    byStatus: Record<string, number>;
    averageSignatures: number;
    completionRate: number;
  } {
    const byStatus: Record<string, number> = {};
    let totalSigs = 0;
    let finalized = 0;

    for (const w of this.store.workflows) {
      byStatus[w.status] = (byStatus[w.status] || 0) + 1;
      totalSigs += w.signatureCount;
      if (w.status === "finalized") finalized++;
    }

    return {
      totalWorkflows: this.store.workflows.length,
      byStatus,
      averageSignatures: this.store.workflows.length > 0
        ? totalSigs / this.store.workflows.length
        : 0,
      completionRate: this.store.workflows.length > 0
        ? finalized / this.store.workflows.length
        : 0,
    };
  }

  // ── Private ──────────────────────────────────────────────

  private findWorkflow(workflowId: string): MultiSigWorkflow | undefined {
    return this.store.workflows.find(w => w.workflowId === workflowId) as MultiSigWorkflow | undefined;
  }

  private getNextRequiredSigner(workflow: MultiSigWorkflow): Counterparty | undefined {
    return workflow.counterparties.find(cp => cp.required && !cp.signedAt && !cp.rejectedAt);
  }

  private computeWorkflowHash(workflow: MultiSigWorkflow): string {
    const sigs = workflow.signatures as Record<string, DigitalSignature>;
    const payload = {
      workflowId: workflow.workflowId,
      documentId: workflow.documentId,
      documentHash: workflow.documentHash,
      threshold: workflow.config.requiredSignatures,
      signatureCount: workflow.signatureCount,
      signatures: Object.keys(sigs).sort().map(email => ({
        email,
        hash: sigs[email].signatureHash,
        signedAt: sigs[email].signedAt,
      })),
      status: workflow.status,
    };
    return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  }

  private load(): WorkflowStore {
    if (fs.existsSync(this.storePath)) {
      try {
        const raw = fs.readFileSync(this.storePath, "utf-8");
        return JSON.parse(raw) as WorkflowStore;
      } catch {
        console.warn("[MULTISIG] Corrupt store — creating new one");
      }
    }
    return {
      engine: "Document Intelligence Engine",
      version: "5.0.0",
      workflows: [],
    };
  }

  private save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2), "utf-8");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _multiSig: MultiSigEngine | null = null;

export function getMultiSigEngine(storeDir?: string): MultiSigEngine {
  if (!_multiSig) {
    _multiSig = new MultiSigEngine(storeDir || ".doc-engine");
  }
  return _multiSig;
}
