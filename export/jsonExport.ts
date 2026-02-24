// ─────────────────────────────────────────────────────────────
// JSON Export — Structured document schema & fingerprint output
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";
import CryptoJS from "crypto-js";
import { DocumentObject, DocumentFingerprint } from "../schema/documentSchema";

/**
 * Export a DocumentObject as structured JSON.
 */
export async function exportJSON(
  doc: DocumentObject,
  outputDir: string,
  options?: { filename?: string; pretty?: boolean }
): Promise<string> {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const baseName = options?.filename || sanitizeFilename(doc.metadata.title);
  const jsonPath = path.join(outputDir, `${baseName}.json`);

  const content = options?.pretty !== false
    ? JSON.stringify(doc, null, 2)
    : JSON.stringify(doc);

  fs.writeFileSync(jsonPath, content, "utf-8");
  console.log(`[EXPORT] JSON → ${jsonPath}`);

  return jsonPath;
}

/**
 * Generate a document fingerprint for integrity verification.
 */
export function generateFingerprint(
  doc: DocumentObject,
  sourceFileContent?: Buffer
): DocumentFingerprint {
  // Hash the document object
  const docString = JSON.stringify(doc);
  const sha256 = crypto.createHash("sha256").update(docString).digest("hex");

  // Hash the source file if provided
  const sourceHash = sourceFileContent
    ? crypto.createHash("sha256").update(sourceFileContent).digest("hex")
    : "";

  // Build Merkle root from section hashes
  const sectionHashes = flattenSections(doc.structure).map((s) =>
    CryptoJS.SHA256(JSON.stringify(s)).toString()
  );
  const merkleRoot = buildMerkleRoot(sectionHashes);

  return {
    sha256,
    merkleRoot,
    version: "1.0.0",
    timestamp: Date.now(),
    sourceHash,
  };
}

/**
 * Export a document fingerprint as JSON.
 */
export async function exportFingerprint(
  fingerprint: DocumentFingerprint,
  outputDir: string,
  options?: { filename?: string }
): Promise<string> {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const baseName = options?.filename || "fingerprint";
  const fpPath = path.join(outputDir, `${baseName}.fingerprint.json`);

  fs.writeFileSync(fpPath, JSON.stringify(fingerprint, null, 2), "utf-8");
  console.log(`[EXPORT] Fingerprint → ${fpPath}`);

  return fpPath;
}

/**
 * Verify a document against a stored fingerprint.
 */
export function verifyFingerprint(
  doc: DocumentObject,
  storedFingerprint: DocumentFingerprint
): { valid: boolean; details: string } {
  const currentHash = crypto
    .createHash("sha256")
    .update(JSON.stringify(doc))
    .digest("hex");

  if (currentHash === storedFingerprint.sha256) {
    return { valid: true, details: "Document integrity verified — hash matches." };
  }

  return {
    valid: false,
    details: `Integrity check FAILED.\nExpected: ${storedFingerprint.sha256}\nActual:   ${currentHash}`,
  };
}

// ── Helpers ──────────────────────────────────────────────────

/** Build a Merkle root from an array of hashes */
function buildMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return CryptoJS.SHA256("empty").toString();
  if (hashes.length === 1) return hashes[0];

  const nextLevel: string[] = [];
  for (let i = 0; i < hashes.length; i += 2) {
    const left = hashes[i];
    const right = i + 1 < hashes.length ? hashes[i + 1] : left;
    nextLevel.push(CryptoJS.SHA256(left + right).toString());
  }

  return buildMerkleRoot(nextLevel);
}

/** Flatten nested sections */
function flattenSections(sections: any[]): any[] {
  const flat: any[] = [];
  const walk = (list: any[]) => {
    for (const s of list) {
      flat.push(s);
      if (s.children?.length > 0) walk(s.children);
    }
  };
  walk(sections);
  return flat;
}

/** Sanitize filename */
function sanitizeFilename(name: string): string {
  return name
    .replace(/[^a-zA-Z0-9\s\-_]/g, "")
    .replace(/\s+/g, "-")
    .toLowerCase()
    .substring(0, 80) || "template";
}
