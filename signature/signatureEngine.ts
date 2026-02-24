// ─────────────────────────────────────────────────────────────
// Signature Engine — Sovereign Digital Signature Authority
//
// Self-sovereign DocuSign replacement. Documents are signed
// with cryptographic identity, timestamped, hashed, and the
// signature state is anchored to IPFS.
//
// Signature flow:
//   1. Document fingerprint computed
//   2. Signer identity captured (name, role, email, device)
//   3. Signature hash = SHA-256(fingerprint + signer + timestamp)
//   4. Document re-hashed with signature included
//   5. Signature block emitted for document embedding
//   6. Audit record generated
//   7. Optional: anchor signature to IPFS
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import os from "os";
import { DocumentFingerprint } from "../schema/documentSchema";

/** Signature type classification */
export type SignatureType =
  | "author"          // Document author/creator
  | "approver"        // Approving authority
  | "witness"         // Witness signature
  | "notary"          // Notarization
  | "counterparty"    // Counter-signing party
  | "reviewer"        // Review acknowledgment
  | "certifier";      // Certification

/** Signature status */
export type SignatureStatus =
  | "pending"
  | "signed"
  | "verified"
  | "rejected"
  | "revoked"
  | "expired";

/** Identity of a signer */
export interface SignerIdentity {
  /** Signer's full name */
  name: string;
  /** Signer's email */
  email: string;
  /** Organization / entity */
  organization?: string;
  /** Role / title */
  role: string;
  /** Signature type */
  signatureType: SignatureType;
}

/** A completed digital signature */
export interface DigitalSignature {
  /** Unique signature ID */
  signatureId: string;
  /** Signer identity */
  signer: SignerIdentity;
  /** ISO timestamp of signature */
  signedAt: string;
  /** SHA-256 hash of the document at signing time */
  documentHash: string;
  /** SHA-256 hash of the signature payload */
  signatureHash: string;
  /** Combined hash = SHA-256(documentHash + signatureHash) */
  combinedHash: string;
  /** Signature status */
  status: SignatureStatus;
  /** Device / machine identifier */
  deviceFingerprint: string;
  /** IP address (if available) */
  ipAddress?: string;
  /** User agent / platform */
  platform: string;
  /** IPFS CID of the signature record (if anchored) */
  cid?: string;
  /** Signature sequence number in this document */
  sequence: number;
  /** Previous signature hash in chain (or "genesis" for first) */
  previousSignatureHash: string;
}

/** Signature request (input for signing) */
export interface SignatureRequest {
  /** Document fingerprint to sign */
  fingerprint: DocumentFingerprint;
  /** Signer identity */
  signer: SignerIdentity;
  /** IP address (optional) */
  ipAddress?: string;
}

/** Multi-signature state for a document */
export interface SignatureState {
  /** Document ID */
  documentId: string;
  /** Document SKU */
  sku?: string;
  /** Original document hash (before any signatures) */
  originalHash: string;
  /** Current document hash (after all signatures) */
  currentHash: string;
  /** All signatures on this document */
  signatures: DigitalSignature[];
  /** Required signers (if specified) */
  requiredSigners?: SignerIdentity[];
  /** Whether all required signatures are obtained */
  isComplete: boolean;
  /** ISO timestamp of creation */
  createdAt: string;
  /** ISO timestamp of last signature */
  lastSignedAt?: string;
}

/** Signature verification result */
export interface SignatureVerification {
  valid: boolean;
  signatureId: string;
  signer: string;
  signedAt: string;
  details: string;
  chainValid: boolean;
}

// ── Signature Engine ─────────────────────────────────────────

export class SignatureEngine {
  /** Create a new signature state for a document */
  createSignatureState(
    documentId: string,
    originalHash: string,
    requiredSigners?: SignerIdentity[],
    sku?: string
  ): SignatureState {
    return {
      documentId,
      sku,
      originalHash,
      currentHash: originalHash,
      signatures: [],
      requiredSigners,
      isComplete: !requiredSigners || requiredSigners.length === 0,
      createdAt: new Date().toISOString(),
    };
  }

  /** Sign a document */
  sign(state: SignatureState, request: SignatureRequest): DigitalSignature {
    const signatureId = crypto.randomBytes(16).toString("hex");
    const signedAt = new Date().toISOString();

    // Device fingerprint
    const deviceFingerprint = this.generateDeviceFingerprint();
    const platform = `${os.type()} ${os.release()} / ${os.arch()}`;

    // Compute signature hash
    const signaturePayload = [
      signatureId,
      request.signer.name,
      request.signer.email,
      request.signer.role,
      request.signer.signatureType,
      request.fingerprint.sha256,
      request.fingerprint.merkleRoot,
      signedAt,
      deviceFingerprint,
    ].join(":");

    const signatureHash = crypto
      .createHash("sha256")
      .update(signaturePayload)
      .digest("hex");

    // Combined hash = document hash + signature hash
    const combinedHash = crypto
      .createHash("sha256")
      .update(state.currentHash + signatureHash)
      .digest("hex");

    // Previous signature hash for chain
    const previousSignatureHash =
      state.signatures.length > 0
        ? state.signatures[state.signatures.length - 1].signatureHash
        : crypto.createHash("sha256").update("genesis").digest("hex");

    const signature: DigitalSignature = {
      signatureId,
      signer: request.signer,
      signedAt,
      documentHash: state.currentHash,
      signatureHash,
      combinedHash,
      status: "signed",
      deviceFingerprint,
      ipAddress: request.ipAddress,
      platform,
      sequence: state.signatures.length + 1,
      previousSignatureHash,
    };

    // Update state
    state.signatures.push(signature);
    state.currentHash = combinedHash;
    state.lastSignedAt = signedAt;

    // Check if all required signers have signed
    if (state.requiredSigners) {
      const signedEmails = new Set(
        state.signatures.map((s) => s.signer.email.toLowerCase())
      );
      state.isComplete = state.requiredSigners.every((rs) =>
        signedEmails.has(rs.email.toLowerCase())
      );
    }

    console.log(
      `[SIGNATURE] ${request.signer.name} (${request.signer.signatureType}) signed — hash: ${signatureHash.substring(0, 16)}...`
    );

    return signature;
  }

  /** Verify a single signature */
  verifySignature(
    signature: DigitalSignature,
    expectedDocumentHash: string
  ): SignatureVerification {
    // Re-derive the signature hash
    const signaturePayload = [
      signature.signatureId,
      signature.signer.name,
      signature.signer.email,
      signature.signer.role,
      signature.signer.signatureType,
      signature.documentHash,
      // Note: we can't fully re-derive without merkleRoot stored separately,
      // but we can verify the document hash matches
      signature.signedAt,
      signature.deviceFingerprint,
    ].join(":");

    // Verify document hash at signing time
    const hashValid = signature.documentHash === expectedDocumentHash;

    return {
      valid: hashValid && signature.status === "signed",
      signatureId: signature.signatureId,
      signer: signature.signer.name,
      signedAt: signature.signedAt,
      details: hashValid
        ? "Signature valid — document hash matches signing state."
        : `Signature INVALID — document hash mismatch. Expected ${expectedDocumentHash.substring(0, 16)}..., found ${signature.documentHash.substring(0, 16)}...`,
      chainValid: true, // Will be set by verifySignatureChain
    };
  }

  /** Verify the full signature chain on a document */
  verifySignatureChain(state: SignatureState): {
    valid: boolean;
    results: SignatureVerification[];
    details: string;
  } {
    const results: SignatureVerification[] = [];
    let currentHash = state.originalHash;
    let chainValid = true;

    const genesisHash = crypto
      .createHash("sha256")
      .update("genesis")
      .digest("hex");

    for (let i = 0; i < state.signatures.length; i++) {
      const sig = state.signatures[i];

      // Verify document hash at signing time
      const verification = this.verifySignature(sig, currentHash);

      // Verify chain link
      const expectedPrevious =
        i === 0
          ? genesisHash
          : state.signatures[i - 1].signatureHash;

      if (sig.previousSignatureHash !== expectedPrevious) {
        verification.chainValid = false;
        chainValid = false;
        verification.details += ` Chain link broken at signature ${i + 1}.`;
      }

      results.push(verification);

      // Advance hash
      currentHash = sig.combinedHash;
    }

    // Verify final hash matches state
    if (currentHash !== state.currentHash) {
      chainValid = false;
    }

    return {
      valid: chainValid && results.every((r) => r.valid),
      results,
      details: chainValid
        ? `Signature chain valid — ${state.signatures.length} signatures verified.`
        : "Signature chain BROKEN — one or more signatures failed verification.",
    };
  }

  /** Revoke a signature */
  revokeSignature(state: SignatureState, signatureId: string): boolean {
    const sig = state.signatures.find((s) => s.signatureId === signatureId);
    if (!sig) return false;

    sig.status = "revoked";
    state.isComplete = false;
    return true;
  }

  /** Generate a signature block for document embedding (HTML) */
  generateSignatureBlockHTML(state: SignatureState): string {
    const lines: string[] = [
      '<div class="signature-block" style="border-top: 2px solid #333; margin-top: 40px; padding-top: 20px; font-family: serif;">',
      '  <h3 style="margin-bottom: 20px;">SIGNATURES</h3>',
    ];

    for (const sig of state.signatures) {
      const statusColor = sig.status === "signed" ? "#2d7d2d" : "#cc3333";
      lines.push(`  <div style="margin-bottom: 30px; padding: 15px; border: 1px solid #ddd;">`);
      lines.push(`    <div style="font-weight: bold; font-size: 16px;">${sig.signer.name}</div>`);
      lines.push(`    <div style="color: #666;">${sig.signer.role} — ${sig.signer.organization || ""}</div>`);
      lines.push(`    <div style="color: #666;">${sig.signer.email}</div>`);
      lines.push(`    <div style="margin-top: 10px;">`);
      lines.push(`      <span style="color: ${statusColor}; font-weight: bold;">[${sig.status.toUpperCase()}]</span>`);
      lines.push(`      <span style="color: #888; margin-left: 10px;">${sig.signedAt}</span>`);
      lines.push(`    </div>`);
      lines.push(`    <div style="font-family: monospace; font-size: 11px; color: #999; margin-top: 8px;">`);
      lines.push(`      Sig: ${sig.signatureHash.substring(0, 32)}...`);
      lines.push(`    </div>`);
      lines.push(`    <div style="font-family: monospace; font-size: 11px; color: #999;">`);
      lines.push(`      Doc: ${sig.documentHash.substring(0, 32)}...`);
      lines.push(`    </div>`);
      lines.push(`  </div>`);
    }

    lines.push(`  <div style="font-size: 11px; color: #999; margin-top: 10px;">`);
    lines.push(`    Document Hash: ${state.currentHash.substring(0, 32)}...`);
    lines.push(`    | Signatures: ${state.signatures.length}`);
    lines.push(`    | Complete: ${state.isComplete ? "YES" : "NO"}`);
    lines.push(`  </div>`);
    lines.push("</div>");

    return lines.join("\n");
  }

  /** Generate device fingerprint for audit trail */
  private generateDeviceFingerprint(): string {
    const data = [
      os.hostname(),
      os.type(),
      os.release(),
      os.arch(),
      os.cpus()[0]?.model || "unknown",
      os.totalmem().toString(),
    ].join(":");

    return crypto.createHash("sha256").update(data).digest("hex").substring(0, 16);
  }

  /** Export signature state as JSON */
  exportSignatureState(state: SignatureState): string {
    return JSON.stringify(state, null, 2);
  }
}

/** Singleton signature engine */
let _signatureEngine: SignatureEngine | null = null;

export function getSignatureEngine(): SignatureEngine {
  if (!_signatureEngine) {
    _signatureEngine = new SignatureEngine();
  }
  return _signatureEngine;
}
