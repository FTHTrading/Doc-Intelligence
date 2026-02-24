// ─────────────────────────────────────────────────────────────
// Canonical Serializer — Deterministic Replay Engine
//
// Guarantees: Same input → Same canonical form → Same hash
//
// Rules:
//   1. Sort all object keys lexicographically (deep)
//   2. Sort all arrays deterministically (by stable key)
//   3. Normalize whitespace (collapse runs, trim)
//   4. Normalize numeric precision (4 decimal places)
//   5. Strip volatile fields (timestamps, random IDs, env data)
//   6. Produce compact JSON (no pretty-print)
//
// The canonical form is the ONLY thing that gets hashed.
// This makes the engine replay-safe and forensically auditable.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import CryptoJS from "crypto-js";
import { DocumentObject, Section, Component } from "../schema/documentSchema";

// ── Volatile Fields (stripped before canonicalization) ────────

/** Fields that change per-run and break determinism */
const VOLATILE_FIELDS = new Set([
  "ingestedAt",
  "timestamp",
  "createdAt",
  "updatedAt",
  "lastAccessed",
  "signedAt",
  "anchoredAt",
  "pushedAt",
  "reviewedAt",
  "finalizedAt",
  "completedAt",
  "registeredAt",
  "deviceFingerprint",
  "ipAddress",
  "platform",
]);

/** Fields containing random component (UUIDs, etc.) */
const RANDOM_ID_FIELDS = new Set([
  "signatureId",
  "sequence",
  "previousSignatureHash",
]);

// ── Core Canonicalization ────────────────────────────────────

/**
 * Produce a deterministic canonical string from any object.
 * Stripping volatile fields, sorting keys, normalizing values.
 */
export function canonicalize(obj: unknown): string {
  const cleaned = deepCleanAndSort(obj);
  return JSON.stringify(cleaned, null, 0);
}

/**
 * Produce a deterministic canonical string from a DocumentObject.
 * Uses document-aware stripping (preserves structure integrity).
 */
export function canonicalizeDocument(doc: DocumentObject): string {
  const canonical: Record<string, unknown> = {};

  // Metadata — strip volatile, keep structural
  canonical.metadata = {
    title: normalizeWhitespace(doc.metadata.title),
    type: doc.metadata.type,
    pageCount: doc.metadata.pageCount,
    language: doc.metadata.language,
    // sourceFile and ingestedAt are volatile — stripped
  };

  // Structure — sort sections deterministically
  canonical.structure = canonicalizeSections(doc.structure);

  // Styles — sort keys
  canonical.styles = sortObjectKeys(doc.styles as unknown as Record<string, unknown>);

  // Components — sort by name then type for stability
  canonical.components = [...doc.components]
    .sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type))
    .map((c) => canonicalizeComponent(c));

  // Semantic tags — sort alphabetically
  canonical.semanticTags = [...doc.semanticTags].sort();

  return JSON.stringify(canonical, null, 0);
}

/**
 * Canonicalize sections array (recursive, deterministic ordering).
 */
function canonicalizeSections(sections: Section[]): unknown[] {
  return sections.map((s) => {
    const canonical: Record<string, unknown> = {};
    canonical.id = s.id;
    canonical.type = s.type;
    canonical.depth = s.depth;
    canonical.label = normalizeWhitespace(s.label);
    canonical.content = normalizeWhitespace(s.content);
    canonical.style = sortObjectKeys(s.style as unknown as Record<string, unknown>);
    if (s.children && s.children.length > 0) {
      canonical.children = canonicalizeSections(s.children);
    } else {
      canonical.children = [];
    }
    return canonical;
  });
}

/**
 * Canonicalize a component.
 */
function canonicalizeComponent(c: Component): Record<string, unknown> {
  const canonical: Record<string, unknown> = {};
  canonical.id = c.id;
  canonical.name = normalizeWhitespace(c.name);
  canonical.type = c.type;
  if (c.columns !== undefined) canonical.columns = c.columns;
  if (c.rows !== undefined) canonical.rows = c.rows;
  if (c.fields) canonical.fields = [...c.fields].sort();
  canonical.style = sortObjectKeys(c.style as unknown as Record<string, unknown>);
  return canonical;
}

// ── Canonical Hash Functions ─────────────────────────────────

/**
 * Compute SHA-256 of a document's canonical form.
 * This hash is deterministic — same input always produces same hash.
 */
export function canonicalHash(doc: DocumentObject): string {
  const canonical = canonicalizeDocument(doc);
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

/**
 * Compute deterministic Merkle root from document sections.
 * Leaves are sorted by section id before tree construction.
 */
export function canonicalMerkleRoot(doc: DocumentObject): string {
  const leaves = flattenSections(doc.structure)
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((s) => {
      const canonical = JSON.stringify({
        id: s.id,
        type: s.type,
        depth: s.depth,
        label: normalizeWhitespace(s.label),
        content: normalizeWhitespace(s.content),
      });
      return CryptoJS.SHA256(canonical).toString();
    });

  if (leaves.length === 0) {
    return CryptoJS.SHA256("empty-document").toString();
  }

  return buildMerkleRoot(leaves);
}

/**
 * Full deterministic fingerprint — hash + merkle root from canonical form.
 */
export interface CanonicalFingerprint {
  canonicalHash: string;
  canonicalMerkleRoot: string;
  sectionCount: number;
  componentCount: number;
  canonicalSize: number;     // byte length of canonical string
}

export function computeCanonicalFingerprint(doc: DocumentObject): CanonicalFingerprint {
  const canonical = canonicalizeDocument(doc);
  const hash = crypto.createHash("sha256").update(canonical).digest("hex");
  const merkle = canonicalMerkleRoot(doc);
  const sections = flattenSections(doc.structure);

  return {
    canonicalHash: hash,
    canonicalMerkleRoot: merkle,
    sectionCount: sections.length,
    componentCount: doc.components.length,
    canonicalSize: Buffer.byteLength(canonical, "utf-8"),
  };
}

// ── Deterministic Replay Verification ────────────────────────

/**
 * Verify that two documents produce the same canonical form.
 * Returns detailed comparison if they differ.
 */
export interface ReplayVerification {
  match: boolean;
  hashA: string;
  hashB: string;
  merkleMatch: boolean;
  canonicalSizeA: number;
  canonicalSizeB: number;
  driftDetails?: string;
}

export function verifyReplay(docA: DocumentObject, docB: DocumentObject): ReplayVerification {
  const fpA = computeCanonicalFingerprint(docA);
  const fpB = computeCanonicalFingerprint(docB);

  const match = fpA.canonicalHash === fpB.canonicalHash;
  const merkleMatch = fpA.canonicalMerkleRoot === fpB.canonicalMerkleRoot;

  let driftDetails: string | undefined;
  if (!match) {
    const canonA = canonicalizeDocument(docA);
    const canonB = canonicalizeDocument(docB);

    // Find first divergence point
    let divergeAt = -1;
    for (let i = 0; i < Math.min(canonA.length, canonB.length); i++) {
      if (canonA[i] !== canonB[i]) {
        divergeAt = i;
        break;
      }
    }

    if (divergeAt === -1 && canonA.length !== canonB.length) {
      driftDetails = `Length mismatch: ${canonA.length} vs ${canonB.length}`;
    } else if (divergeAt >= 0) {
      const contextStart = Math.max(0, divergeAt - 50);
      const contextEnd = Math.min(divergeAt + 50, Math.max(canonA.length, canonB.length));
      driftDetails = `First divergence at byte ${divergeAt}:\n` +
        `  A: ...${canonA.substring(contextStart, contextEnd)}...\n` +
        `  B: ...${canonB.substring(contextStart, contextEnd)}...`;
    }
  }

  return {
    match,
    hashA: fpA.canonicalHash,
    hashB: fpB.canonicalHash,
    merkleMatch,
    canonicalSizeA: fpA.canonicalSize,
    canonicalSizeB: fpB.canonicalSize,
    driftDetails,
  };
}

// ── Hash Stability Test ──────────────────────────────────────

/**
 * Run N rounds of canonical hashing on the same document.
 * If any round produces a different hash, determinism is broken.
 */
export interface StabilityResult {
  rounds: number;
  stable: boolean;
  hashes: string[];
  merkleRoots: string[];
  driftRound?: number;
}

export function runHashStabilityTest(doc: DocumentObject, rounds: number = 5): StabilityResult {
  const hashes: string[] = [];
  const merkleRoots: string[] = [];

  for (let i = 0; i < rounds; i++) {
    hashes.push(canonicalHash(doc));
    merkleRoots.push(canonicalMerkleRoot(doc));
  }

  const baseHash = hashes[0];
  const baseMerkle = merkleRoots[0];
  let driftRound: number | undefined;

  for (let i = 1; i < rounds; i++) {
    if (hashes[i] !== baseHash || merkleRoots[i] !== baseMerkle) {
      driftRound = i;
      break;
    }
  }

  return {
    rounds,
    stable: driftRound === undefined,
    hashes,
    merkleRoots,
    driftRound,
  };
}

// ── Deep Utility Functions ───────────────────────────────────

/**
 * Deep-clone an object, sorting all keys, stripping volatile fields,
 * normalizing strings and numbers.
 */
function deepCleanAndSort(obj: unknown): unknown {
  if (obj === null || obj === undefined) return null;

  if (typeof obj === "string") {
    return normalizeWhitespace(obj);
  }

  if (typeof obj === "number") {
    return normalizeNumber(obj);
  }

  if (typeof obj === "boolean") {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(deepCleanAndSort);
  }

  if (typeof obj === "object") {
    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    for (const key of keys) {
      if (VOLATILE_FIELDS.has(key)) continue;
      if (RANDOM_ID_FIELDS.has(key)) continue;
      sorted[key] = deepCleanAndSort((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }

  return String(obj);
}

/**
 * Sort object keys lexicographically (shallow).
 */
function sortObjectKeys(obj: Record<string, unknown>): Record<string, unknown> {
  if (!obj || typeof obj !== "object") return {};
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = obj[key];
  }
  return sorted;
}

/**
 * Normalize whitespace: collapse runs, trim.
 */
function normalizeWhitespace(str: string): string {
  if (!str) return "";
  return str.replace(/\s+/g, " ").trim();
}

/**
 * Normalize number precision to 4 decimal places.
 */
function normalizeNumber(n: number): number {
  if (Number.isInteger(n)) return n;
  return Math.round(n * 10000) / 10000;
}

/**
 * Flatten nested sections into a flat array.
 */
function flattenSections(sections: Section[]): Section[] {
  const flat: Section[] = [];
  const walk = (list: Section[]) => {
    for (const s of list) {
      flat.push(s);
      if (s.children && s.children.length > 0) walk(s.children);
    }
  };
  walk(sections);
  return flat;
}

/**
 * Build Merkle root from an array of hex-string leaf hashes.
 */
function buildMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return CryptoJS.SHA256("empty").toString();
  if (hashes.length === 1) return hashes[0];

  const sorted = [...hashes].sort();
  let level = sorted;

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        const pair = level[i] < level[i + 1]
          ? level[i] + level[i + 1]
          : level[i + 1] + level[i];
        next.push(CryptoJS.SHA256(pair).toString());
      } else {
        next.push(level[i]);
      }
    }
    level = next;
  }

  return level[0];
}
