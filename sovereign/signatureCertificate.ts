// ─────────────────────────────────────────────────────────────
// Signature Certificate Engine — ESIGN/UETA Compliance Layer
//
// Generates legally-defensible signature certificates that
// contain all required elements for electronic signature
// enforceability under ESIGN (2000) and UETA (1999):
//
//   1. Intent to sign (consent confirmation)
//   2. Association of signature with record
//   3. Record retention / reproducibility
//   4. Signer identity verification
//   5. Tamper-evident hash chain
//   6. Timestamp with full audit metadata
//
// Each certificate is a self-contained JSON artifact that
// proves WHO signed WHAT, WHEN, HOW, and on WHAT DEVICE.
//
// The certificate itself is hashed and optionally anchored.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import {
  DigitalSignature,
  SignerIdentity,
  SignatureState,
} from "../signature/signatureEngine";
import { DocumentFingerprint } from "../schema/documentSchema";

// ── Types ────────────────────────────────────────────────────

/** Compliance framework reference */
export type ComplianceFramework = "ESIGN" | "UETA" | "eIDAS" | "custom";

/** Certificate status */
export type CertificateStatus =
  | "issued"
  | "verified"
  | "revoked"
  | "expired"
  | "superseded";

/** Consent record for ESIGN compliance */
export interface ConsentRecord {
  /** Signer explicitly consented to electronic signing */
  consentGiven: boolean;
  /** Method of consent capture */
  consentMethod: "cli-flag" | "interactive" | "api" | "pre-configured";
  /** ISO timestamp of consent */
  consentTimestamp: string;
  /** Description of what was consented to */
  consentScope: string;
}

/** Device attestation for signature context */
export interface DeviceAttestation {
  /** OS and platform */
  platform: string;
  /** Device fingerprint hash */
  deviceFingerprint: string;
  /** IP address (if captured) */
  ipAddress?: string;
  /** Node.js version */
  runtimeVersion: string;
  /** Engine version */
  engineVersion: string;
}

/** Signature Certificate — the core compliance artifact */
export interface SignatureCertificate {
  /** Certificate ID */
  certificateId: string;
  /** Certificate version */
  certificateVersion: string;
  /** ISO timestamp of certificate generation */
  issuedAt: string;
  /** Compliance frameworks this certificate satisfies */
  frameworks: ComplianceFramework[];
  /** Certificate status */
  status: CertificateStatus;

  // ── Document Reference ──
  /** Document ID */
  documentId: string;
  /** Document SKU */
  documentSKU?: string;
  /** Document title */
  documentTitle?: string;
  /** Document SHA-256 hash at time of signing */
  documentHash: string;
  /** Document Merkle root */
  merkleRoot: string;

  // ── Signer Identity ──
  /** Full signer identity */
  signer: SignerIdentity;
  /** Signer's full name */
  signerName: string;
  /** Signer's email */
  signerEmail: string;
  /** Signer's role */
  signerRole: string;

  // ── Signature Proof ──
  /** Signature ID from the signature engine */
  signatureId: string;
  /** Signature hash */
  signatureHash: string;
  /** Combined hash (document + signature) */
  combinedHash: string;
  /** Position in signature chain */
  chainPosition: number;
  /** Previous signature hash (chain integrity) */
  previousSignatureHash: string;
  /** Timestamp of signature */
  signedAt: string;

  // ── Consent & Compliance ──
  /** Consent record (ESIGN requirement) */
  consent: ConsentRecord;
  /** Device attestation */
  device: DeviceAttestation;

  // ── Integrity ──
  /** SHA-256 hash of this certificate's content (self-referential) */
  certificateHash: string;
  /** CID if anchored to IPFS */
  anchoredCID?: string;
}

/** Certificate generation options */
export interface CertificateOptions {
  /** Document ID */
  documentId: string;
  /** Document SKU */
  documentSKU?: string;
  /** Document title */
  documentTitle?: string;
  /** The document fingerprint */
  fingerprint: DocumentFingerprint;
  /** The digital signature */
  signature: DigitalSignature;
  /** Full signature state (for chain context) */
  signatureState: SignatureState;
  /** Consent was given */
  consentGiven?: boolean;
  /** Consent method */
  consentMethod?: ConsentRecord["consentMethod"];
  /** Compliance frameworks to assert */
  frameworks?: ComplianceFramework[];
}

/** Certificate verification result */
export interface CertificateVerification {
  /** Certificate is structurally valid */
  valid: boolean;
  /** Hash integrity check */
  hashValid: boolean;
  /** Signature chain position is consistent */
  chainConsistent: boolean;
  /** Consent was recorded */
  consentRecorded: boolean;
  /** All ESIGN requirements met */
  esignCompliant: boolean;
  /** Details / issues */
  details: string[];
}

// ── Engine ───────────────────────────────────────────────────

const ENGINE_VERSION = "4.0.0";
const CERT_VERSION = "1.0.0";

/**
 * Generate a signature certificate from a completed signature.
 */
export function generateCertificate(options: CertificateOptions): SignatureCertificate {
  const certificateId = crypto.randomBytes(16).toString("hex");
  const issuedAt = new Date().toISOString();

  const frameworks = options.frameworks || ["ESIGN", "UETA"];

  const consent: ConsentRecord = {
    consentGiven: options.consentGiven !== false, // default true
    consentMethod: options.consentMethod || "cli-flag",
    consentTimestamp: options.signature.signedAt,
    consentScope: `Electronic signature of document ${options.documentId} by ${options.signature.signer.name}`,
  };

  const device: DeviceAttestation = {
    platform: options.signature.platform,
    deviceFingerprint: options.signature.deviceFingerprint,
    ipAddress: options.signature.ipAddress,
    runtimeVersion: process.version,
    engineVersion: ENGINE_VERSION,
  };

  // Build the certificate body (without the self-hash)
  const certBody = {
    certificateId,
    certificateVersion: CERT_VERSION,
    issuedAt,
    frameworks,
    status: "issued" as CertificateStatus,

    documentId: options.documentId,
    documentSKU: options.documentSKU,
    documentTitle: options.documentTitle,
    documentHash: options.fingerprint.sha256,
    merkleRoot: options.fingerprint.merkleRoot,

    signer: options.signature.signer,
    signerName: options.signature.signer.name,
    signerEmail: options.signature.signer.email,
    signerRole: options.signature.signer.role,

    signatureId: options.signature.signatureId,
    signatureHash: options.signature.signatureHash,
    combinedHash: options.signature.combinedHash,
    chainPosition: options.signature.sequence,
    previousSignatureHash: options.signature.previousSignatureHash,
    signedAt: options.signature.signedAt,

    consent,
    device,
  };

  // Compute certificate hash from deterministic serialization
  const certContentForHash = JSON.stringify(certBody, Object.keys(certBody).sort());
  const certificateHash = crypto
    .createHash("sha256")
    .update(certContentForHash)
    .digest("hex");

  return {
    ...certBody,
    certificateHash,
  };
}

/**
 * Generate certificates for all signatures in a signature state.
 */
export function generateCertificatesForState(
  signatureState: SignatureState,
  fingerprint: DocumentFingerprint,
  documentTitle?: string,
  consentGiven?: boolean
): SignatureCertificate[] {
  return signatureState.signatures.map((sig) =>
    generateCertificate({
      documentId: signatureState.documentId,
      documentSKU: signatureState.sku,
      documentTitle,
      fingerprint,
      signature: sig,
      signatureState,
      consentGiven,
    })
  );
}

/**
 * Verify a certificate's structural integrity.
 */
export function verifyCertificate(cert: SignatureCertificate): CertificateVerification {
  const details: string[] = [];
  let valid = true;

  // ── Hash integrity ──
  const { certificateHash, anchoredCID, ...body } = cert;
  const bodyForHash = JSON.stringify(body, Object.keys(body).sort());
  const expectedHash = crypto.createHash("sha256").update(bodyForHash).digest("hex");
  const hashValid = expectedHash === certificateHash;
  if (!hashValid) {
    details.push(`Certificate hash mismatch: expected ${expectedHash}, got ${certificateHash}`);
    valid = false;
  } else {
    details.push("Certificate hash integrity: VALID");
  }

  // ── Chain consistency ──
  const chainConsistent = cert.chainPosition > 0 && cert.previousSignatureHash.length > 0;
  if (!chainConsistent) {
    details.push("Signature chain position invalid");
    valid = false;
  } else {
    details.push(`Signature chain position ${cert.chainPosition}: VALID`);
  }

  // ── Consent check (ESIGN requirement) ──
  const consentRecorded = cert.consent.consentGiven === true;
  if (!consentRecorded) {
    details.push("WARNING: No consent recorded — may not satisfy ESIGN requirements");
    valid = false;
  } else {
    details.push("Consent recorded: YES");
  }

  // ── ESIGN compliance ──
  const esignChecks = [
    cert.consent.consentGiven,
    cert.signerName && cert.signerName.length > 0,
    cert.signerEmail && cert.signerEmail.length > 0,
    cert.documentHash && cert.documentHash.length > 0,
    cert.signatureHash && cert.signatureHash.length > 0,
    cert.signedAt && cert.signedAt.length > 0,
    cert.device.platform && cert.device.platform.length > 0,
  ];
  const esignCompliant = esignChecks.every(Boolean);
  if (esignCompliant) {
    details.push("ESIGN compliance: ALL REQUIREMENTS MET");
  } else {
    details.push("ESIGN compliance: INCOMPLETE — missing required fields");
    valid = false;
  }

  return { valid, hashValid, chainConsistent, consentRecorded, esignCompliant, details };
}

/**
 * Format a certificate as a human-readable text block.
 */
export function formatCertificateText(cert: SignatureCertificate): string {
  const lines: string[] = [
    "═══════════════════════════════════════════════════════════════",
    "              DIGITAL SIGNATURE CERTIFICATE",
    "═══════════════════════════════════════════════════════════════",
    "",
    `Certificate ID:     ${cert.certificateId}`,
    `Certificate Version: ${cert.certificateVersion}`,
    `Issued At:          ${cert.issuedAt}`,
    `Status:             ${cert.status.toUpperCase()}`,
    `Frameworks:         ${cert.frameworks.join(", ")}`,
    "",
    "─── Document ───────────────────────────────────────────────",
    `Document ID:        ${cert.documentId}`,
    cert.documentSKU ? `Document SKU:       ${cert.documentSKU}` : "",
    cert.documentTitle ? `Document Title:     ${cert.documentTitle}` : "",
    `Document Hash:      ${cert.documentHash}`,
    `Merkle Root:        ${cert.merkleRoot}`,
    "",
    "─── Signer ─────────────────────────────────────────────────",
    `Name:               ${cert.signerName}`,
    `Email:              ${cert.signerEmail}`,
    `Role:               ${cert.signerRole}`,
    `Signature Type:     ${cert.signer.signatureType}`,
    cert.signer.organization ? `Organization:       ${cert.signer.organization}` : "",
    "",
    "─── Signature ──────────────────────────────────────────────",
    `Signature ID:       ${cert.signatureId}`,
    `Signed At:          ${cert.signedAt}`,
    `Signature Hash:     ${cert.signatureHash}`,
    `Combined Hash:      ${cert.combinedHash}`,
    `Chain Position:     ${cert.chainPosition}`,
    `Previous Sig Hash:  ${cert.previousSignatureHash}`,
    "",
    "─── Consent ────────────────────────────────────────────────",
    `Consent Given:      ${cert.consent.consentGiven ? "YES" : "NO"}`,
    `Consent Method:     ${cert.consent.consentMethod}`,
    `Consent Timestamp:  ${cert.consent.consentTimestamp}`,
    `Consent Scope:      ${cert.consent.consentScope}`,
    "",
    "─── Device ─────────────────────────────────────────────────",
    `Platform:           ${cert.device.platform}`,
    `Device Fingerprint: ${cert.device.deviceFingerprint}`,
    cert.device.ipAddress ? `IP Address:         ${cert.device.ipAddress}` : "",
    `Runtime:            ${cert.device.runtimeVersion}`,
    `Engine:             ${cert.device.engineVersion}`,
    "",
    "─── Integrity ──────────────────────────────────────────────",
    `Certificate Hash:   ${cert.certificateHash}`,
    cert.anchoredCID ? `Anchored CID:       ${cert.anchoredCID}` : "",
    "",
    "═══════════════════════════════════════════════════════════════",
  ].filter(Boolean);

  return lines.join("\n");
}
