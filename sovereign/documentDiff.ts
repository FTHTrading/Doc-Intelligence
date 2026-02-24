// ─────────────────────────────────────────────────────────────
// Document Diff Engine — Forensic-Grade Document Comparison
//
// Compares two versions of a document and produces:
//
//   1. Section-level diffs (added, removed, modified)
//   2. Content-level diffs (text deltas)
//   3. Merkle diff proofs (cryptographic proof of what changed)
//   4. Metadata diff (fingerprint, timestamps, hashes)
//   5. Structural diff (section tree changes)
//   6. Semantic tag diff (tag additions/removals)
//   7. Forensic summary (human-readable change report)
//
// Use cases:
//   - Draft vs Signed comparison
//   - Version history analysis
//   - Compliance audit (what changed between reviews)
//   - Tamper detection
//
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import { DocumentObject, Section } from "../schema/documentSchema";
import { canonicalHash, canonicalMerkleRoot } from "../sovereign/canonicalizer";

// ── Types ────────────────────────────────────────────────────

/** Change type classification */
export type ChangeType = "added" | "removed" | "modified" | "unchanged" | "moved";

/** A single section diff entry */
export interface SectionDiff {
  /** Section ID */
  sectionId: string;
  /** Change type */
  change: ChangeType;
  /** Section label (from whichever version exists) */
  label: string;
  /** Content before (null if added) */
  before: string | null;
  /** Content after (null if removed) */
  after: string | null;
  /** SHA-256 of content before */
  hashBefore: string | null;
  /** SHA-256 of content after */
  hashAfter: string | null;
  /** Depth in section tree */
  depth: number;
  /** Content difference size in bytes */
  deltaBytes: number;
}

/** Metadata diff */
export interface MetadataDiff {
  field: string;
  before: string;
  after: string;
  changed: boolean;
}

/** Merkle diff proof — cryptographic proof of changes */
export interface MerkleDiffProof {
  /** Merkle root of document A */
  rootA: string;
  /** Merkle root of document B */
  rootB: string;
  /** Section hashes for A */
  leavesA: Array<{ sectionId: string; hash: string }>;
  /** Section hashes for B */
  leavesB: Array<{ sectionId: string; hash: string }>;
  /** Changed leaf IDs */
  changedLeaves: string[];
  /** Proof hash (SHA-256 of the diff itself) */
  proofHash: string;
  /** Root match */
  rootsMatch: boolean;
}

/** Full document diff result */
export interface DocumentDiffResult {
  /** Diff ID */
  diffId: string;
  /** Label for document A */
  labelA: string;
  /** Label for document B */
  labelB: string;
  /** Canonical hash of A */
  hashA: string;
  /** Canonical hash of B */
  hashB: string;
  /** Whether documents are identical */
  identical: boolean;
  /** Section-level diffs */
  sections: SectionDiff[];
  /** Metadata diffs */
  metadata: MetadataDiff[];
  /** Semantic tag diffs */
  tagDiffs: {
    added: string[];
    removed: string[];
    unchanged: string[];
  };
  /** Merkle diff proof */
  merkleProof: MerkleDiffProof;
  /** Summary statistics */
  stats: {
    totalSectionsA: number;
    totalSectionsB: number;
    added: number;
    removed: number;
    modified: number;
    unchanged: number;
    totalDeltaBytes: number;
  };
  /** Computed at */
  computedAt: string;
  /** Diff hash (integrity of this result) */
  diffHash: string;
}

// ── Diff Engine ──────────────────────────────────────────────

/**
 * Compare two DocumentObjects and produce a forensic diff.
 */
export function diffDocuments(
  docA: DocumentObject,
  docB: DocumentObject,
  labelA: string = "Version A",
  labelB: string = "Version B"
): DocumentDiffResult {
  const diffId = crypto.randomBytes(12).toString("hex");
  const hashA = canonicalHash(docA);
  const hashB = canonicalHash(docB);

  // Quick identity check
  const identical = hashA === hashB;

  // Section diffs
  const sectionsA = flattenSections(docA.structure);
  const sectionsB = flattenSections(docB.structure);
  const sectionDiffs = diffSections(sectionsA, sectionsB);

  // Metadata diffs
  const metadataDiffs = diffMetadata(docA, docB);

  // Tag diffs
  const tagDiffs = diffTags(docA.semanticTags, docB.semanticTags);

  // Merkle proof
  const merkleProof = buildMerkleDiffProof(sectionsA, sectionsB);

  // Stats
  const stats = {
    totalSectionsA: sectionsA.length,
    totalSectionsB: sectionsB.length,
    added: sectionDiffs.filter(d => d.change === "added").length,
    removed: sectionDiffs.filter(d => d.change === "removed").length,
    modified: sectionDiffs.filter(d => d.change === "modified").length,
    unchanged: sectionDiffs.filter(d => d.change === "unchanged").length,
    totalDeltaBytes: sectionDiffs.reduce((sum, d) => sum + Math.abs(d.deltaBytes), 0),
  };

  const resultBody = {
    diffId,
    labelA,
    labelB,
    hashA,
    hashB,
    identical,
    sections: sectionDiffs,
    metadata: metadataDiffs,
    tagDiffs,
    merkleProof,
    stats,
    computedAt: new Date().toISOString(),
  };

  const diffHash = crypto
    .createHash("sha256")
    .update(JSON.stringify({
      hashA, hashB, identical,
      sections: sectionDiffs.map(s => `${s.sectionId}:${s.change}:${s.hashBefore}:${s.hashAfter}`),
      stats,
    }))
    .digest("hex");

  return { ...resultBody, diffHash };
}

// ── Section Flattening ───────────────────────────────────────

interface FlatSection {
  id: string;
  label: string;
  content: string;
  depth: number;
  hash: string;
}

function flattenSections(structure: Section[], depth: number = 0): FlatSection[] {
  const result: FlatSection[] = [];
  for (const section of structure) {
    const content = section.content || "";
    result.push({
      id: section.id,
      label: section.label || "",
      content,
      depth,
      hash: crypto.createHash("sha256").update(content).digest("hex"),
    });
    if (section.children && section.children.length > 0) {
      result.push(...flattenSections(section.children, depth + 1));
    }
  }
  return result;
}

// ── Section Diff ─────────────────────────────────────────────

function diffSections(sectionsA: FlatSection[], sectionsB: FlatSection[]): SectionDiff[] {
  const diffs: SectionDiff[] = [];
  const mapA = new Map(sectionsA.map(s => [s.id, s]));
  const mapB = new Map(sectionsB.map(s => [s.id, s]));
  const allIds = new Set([...mapA.keys(), ...mapB.keys()]);

  for (const id of allIds) {
    const a = mapA.get(id);
    const b = mapB.get(id);

    if (a && b) {
      // Both exist — check if modified
      const change: ChangeType = a.hash === b.hash ? "unchanged" : "modified";
      diffs.push({
        sectionId: id,
        change,
        label: b.label || a.label,
        before: a.content,
        after: b.content,
        hashBefore: a.hash,
        hashAfter: b.hash,
        depth: b.depth,
        deltaBytes: Buffer.byteLength(b.content, "utf-8") - Buffer.byteLength(a.content, "utf-8"),
      });
    } else if (a && !b) {
      // Removed in B
      diffs.push({
        sectionId: id,
        change: "removed",
        label: a.label,
        before: a.content,
        after: null,
        hashBefore: a.hash,
        hashAfter: null,
        depth: a.depth,
        deltaBytes: -Buffer.byteLength(a.content, "utf-8"),
      });
    } else if (!a && b) {
      // Added in B
      diffs.push({
        sectionId: id,
        change: "added",
        label: b.label,
        before: null,
        after: b.content,
        hashBefore: null,
        hashAfter: b.hash,
        depth: b.depth,
        deltaBytes: Buffer.byteLength(b.content, "utf-8"),
      });
    }
  }

  // Sort: removed first, then modified, then unchanged, then added
  const order: Record<string, number> = { removed: 0, modified: 1, unchanged: 2, added: 3 };
  diffs.sort((a, b) => (order[a.change] ?? 4) - (order[b.change] ?? 4));

  return diffs;
}

// ── Metadata Diff ────────────────────────────────────────────

function diffMetadata(docA: DocumentObject, docB: DocumentObject): MetadataDiff[] {
  const diffs: MetadataDiff[] = [];
  const fields: Array<{ field: string; a: string; b: string }> = [
    { field: "title", a: docA.metadata.title, b: docB.metadata.title },
    { field: "type", a: docA.metadata.type, b: docB.metadata.type },
    { field: "pageCount", a: String(docA.metadata.pageCount), b: String(docB.metadata.pageCount) },
    { field: "sourceFile", a: docA.metadata.sourceFile, b: docB.metadata.sourceFile },
    { field: "language", a: docA.metadata.language || "", b: docB.metadata.language || "" },
    { field: "sectionCount", a: String(docA.structure.length), b: String(docB.structure.length) },
    { field: "semanticTags", a: String(docA.semanticTags.length), b: String(docB.semanticTags.length) },
    { field: "components", a: String(docA.components.length), b: String(docB.components.length) },
  ];

  for (const f of fields) {
    diffs.push({
      field: f.field,
      before: f.a,
      after: f.b,
      changed: f.a !== f.b,
    });
  }

  return diffs;
}

// ── Tag Diff ─────────────────────────────────────────────────

function diffTags(tagsA: string[], tagsB: string[]): { added: string[]; removed: string[]; unchanged: string[] } {
  const setA = new Set(tagsA);
  const setB = new Set(tagsB);
  return {
    added: tagsB.filter(t => !setA.has(t)),
    removed: tagsA.filter(t => !setB.has(t)),
    unchanged: tagsA.filter(t => setB.has(t)),
  };
}

// ── Merkle Diff Proof ────────────────────────────────────────

function buildMerkleDiffProof(sectionsA: FlatSection[], sectionsB: FlatSection[]): MerkleDiffProof {
  const leavesA = sectionsA.map(s => ({ sectionId: s.id, hash: s.hash }));
  const leavesB = sectionsB.map(s => ({ sectionId: s.id, hash: s.hash }));

  const rootA = computeMerkleRoot(leavesA.map(l => l.hash));
  const rootB = computeMerkleRoot(leavesB.map(l => l.hash));

  // Find changed leaves
  const mapA = new Map(leavesA.map(l => [l.sectionId, l.hash]));
  const changedLeaves: string[] = [];
  for (const leaf of leavesB) {
    const hashA = mapA.get(leaf.sectionId);
    if (hashA !== leaf.hash) {
      changedLeaves.push(leaf.sectionId);
    }
  }
  // Also add sections removed from A
  const setB = new Set(leavesB.map(l => l.sectionId));
  for (const leaf of leavesA) {
    if (!setB.has(leaf.sectionId)) {
      changedLeaves.push(leaf.sectionId);
    }
  }

  const proofPayload = JSON.stringify({ rootA, rootB, changedLeaves: changedLeaves.sort() });
  const proofHash = crypto.createHash("sha256").update(proofPayload).digest("hex");

  return {
    rootA,
    rootB,
    leavesA,
    leavesB,
    changedLeaves,
    proofHash,
    rootsMatch: rootA === rootB,
  };
}

function computeMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return crypto.createHash("sha256").update("empty").digest("hex");
  if (hashes.length === 1) return hashes[0];

  const level: string[] = [];
  for (let i = 0; i < hashes.length; i += 2) {
    const left = hashes[i];
    const right = i + 1 < hashes.length ? hashes[i + 1] : left;
    level.push(crypto.createHash("sha256").update(left + right).digest("hex"));
  }
  return computeMerkleRoot(level);
}

// ── Report Formatting ────────────────────────────────────────

/**
 * Format a diff result as a human-readable report.
 */
export function formatDiffReport(diff: DocumentDiffResult): string {
  const lines: string[] = [];
  lines.push(`╔══════════════════════════════════════════════════════╗`);
  lines.push(`║  DOCUMENT DIFF REPORT                               ║`);
  lines.push(`╚══════════════════════════════════════════════════════╝`);
  lines.push(``);
  lines.push(`  ${diff.labelA}  ↔  ${diff.labelB}`);
  lines.push(``);
  lines.push(`  Hash A: ${diff.hashA.substring(0, 32)}...`);
  lines.push(`  Hash B: ${diff.hashB.substring(0, 32)}...`);
  lines.push(`  Identical: ${diff.identical ? "YES" : "NO"}`);
  lines.push(``);

  lines.push(`  ─── Summary ──────────────────────────────────────`);
  lines.push(`  Sections A: ${diff.stats.totalSectionsA} | Sections B: ${diff.stats.totalSectionsB}`);
  lines.push(`  Added: ${diff.stats.added} | Removed: ${diff.stats.removed} | Modified: ${diff.stats.modified} | Unchanged: ${diff.stats.unchanged}`);
  lines.push(`  Delta bytes: ${diff.stats.totalDeltaBytes > 0 ? "+" : ""}${diff.stats.totalDeltaBytes}`);
  lines.push(``);

  // Section changes
  const changes = diff.sections.filter(s => s.change !== "unchanged");
  if (changes.length > 0) {
    lines.push(`  ─── Section Changes (${changes.length}) ──────────────────`);
    for (const s of changes) {
      const icon = s.change === "added" ? "+" : s.change === "removed" ? "-" : "~";
      const label = s.label || s.sectionId;
      lines.push(`  [${icon}] ${label} (${s.change})`);
      if (s.change === "modified" && s.before && s.after) {
        const beforeSnip = s.before.substring(0, 60).replace(/\n/g, " ");
        const afterSnip = s.after.substring(0, 60).replace(/\n/g, " ");
        lines.push(`      Before: "${beforeSnip}..."`);
        lines.push(`      After:  "${afterSnip}..."`);
      }
      if (s.deltaBytes !== 0) {
        lines.push(`      Delta: ${s.deltaBytes > 0 ? "+" : ""}${s.deltaBytes} bytes`);
      }
    }
    lines.push(``);
  }

  // Metadata changes
  const metaChanges = diff.metadata.filter(m => m.changed);
  if (metaChanges.length > 0) {
    lines.push(`  ─── Metadata Changes (${metaChanges.length}) ─────────────────`);
    for (const m of metaChanges) {
      lines.push(`  ${m.field}: "${m.before}" → "${m.after}"`);
    }
    lines.push(``);
  }

  // Tag changes
  if (diff.tagDiffs.added.length > 0 || diff.tagDiffs.removed.length > 0) {
    lines.push(`  ─── Tag Changes ──────────────────────────────────`);
    if (diff.tagDiffs.added.length > 0) lines.push(`  Added: ${diff.tagDiffs.added.join(", ")}`);
    if (diff.tagDiffs.removed.length > 0) lines.push(`  Removed: ${diff.tagDiffs.removed.join(", ")}`);
    lines.push(``);
  }

  // Merkle proof
  lines.push(`  ─── Merkle Diff Proof ────────────────────────────`);
  lines.push(`  Root A: ${diff.merkleProof.rootA.substring(0, 32)}...`);
  lines.push(`  Root B: ${diff.merkleProof.rootB.substring(0, 32)}...`);
  lines.push(`  Roots match: ${diff.merkleProof.rootsMatch ? "YES" : "NO"}`);
  lines.push(`  Changed leaves: ${diff.merkleProof.changedLeaves.length}`);
  lines.push(`  Proof hash: ${diff.merkleProof.proofHash.substring(0, 32)}...`);
  lines.push(``);

  lines.push(`  ─── Integrity ────────────────────────────────────`);
  lines.push(`  Diff ID: ${diff.diffId}`);
  lines.push(`  Diff Hash: ${diff.diffHash}`);
  lines.push(`  Computed: ${diff.computedAt}`);
  lines.push(``);

  return lines.join("\n");
}
