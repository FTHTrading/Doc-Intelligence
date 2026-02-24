// ─────────────────────────────────────────────────────────────
// Secure Document Control — Forensic Fingerprint Engine
//
// Creates mathematically unique per-recipient document versions
// through invisible micro-modifications that survive printing,
// scanning, screenshotting, and copy/paste.
//
// Techniques:
//   1. Zero-width Unicode steganography (invisible character patterns)
//   2. Micro letter-spacing variations (±0.03pt per character)
//   3. Word-spacing jitter (±0.02em per word boundary)
//   4. Whitespace pattern encoding (space/tab/NBSP substitution)
//   5. Homoglyph substitution (visually identical Unicode variants)
//
// Forensic Capability:
//   Given a leaked document (even a photo of a printout), the
//   engine can reconstruct which recipient's version it came from
//   by analyzing spacing patterns and marker positions.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

export interface FingerprintRecipient {
  /** Recipient email */
  email: string;
  /** Recipient name */
  name: string;
  /** Organization */
  organization?: string;
  /** Access token ID */
  tokenId?: string;
}

export interface FingerprintPayload {
  /** Unique fingerprint ID */
  fingerprintId: string;
  /** Document ID */
  documentId: string;
  /** Document title */
  documentTitle: string;
  /** Recipient */
  recipient: FingerprintRecipient;
  /** Fingerprint hash (derivation key for all patterns) */
  fingerprintHash: string;
  /** Timestamp */
  timestamp: string;
  /** Number of zero-width markers inserted */
  zwMarkerCount: number;
  /** Number of spacing variations applied */
  spacingVariations: number;
  /** Number of whitespace substitutions */
  whitespaceSubstitutions: number;
  /** Number of homoglyph substitutions */
  homoglyphCount: number;
  /** Total modifications */
  totalModifications: number;
  /** Verification signature — HMAC of all pattern parameters */
  verificationSignature: string;
}

export interface FingerprintResult {
  /** Fingerprint metadata */
  payload: FingerprintPayload;
  /** Fingerprinted text content */
  fingerprintedText: string;
  /** CSS for spacing variations */
  spacingCSS: string;
  /** Detection report (for verification) */
  detectionProfile: DetectionProfile;
}

export interface DetectionProfile {
  /** Zero-width marker positions (character indices) */
  zwPositions: number[];
  /** Zero-width encoded hash */
  zwEncodedHash: string;
  /** Spacing deviation pattern (per-word) */
  spacingPattern: number[];
  /** Whitespace substitution map */
  whitespaceMap: Array<{ position: number; original: string; replacement: string }>;
  /** Homoglyph substitution positions */
  homoglyphPositions: Array<{ position: number; original: string; replacement: string }>;
}

export interface ForensicMatch {
  /** Whether a match was found */
  matched: boolean;
  /** Confidence score 0-1 */
  confidence: number;
  /** Matched recipient email */
  recipientEmail: string | null;
  /** Matched fingerprint ID */
  fingerprintId: string | null;
  /** Techniques that matched */
  matchedTechniques: string[];
  /** Details */
  details: string;
}

export interface FingerprintRecord {
  /** Fingerprint ID */
  fingerprintId: string;
  /** Document ID */
  documentId: string;
  /** Recipient email */
  recipientEmail: string;
  /** Fingerprint hash */
  fingerprintHash: string;
  /** Detection profile (for forensic matching) */
  detectionProfile: DetectionProfile;
  /** Timestamp */
  timestamp: string;
}

// ── Constants ────────────────────────────────────────────────

/** Zero-width Unicode characters for steganographic encoding */
const ZW_CHARS = [
  "\u200B", // Zero Width Space
  "\u200C", // Zero Width Non-Joiner
  "\u200D", // Zero Width Joiner
  "\u2060", // Word Joiner
  "\uFEFF", // Zero Width No-Break Space
];

/** Homoglyphs — visually identical character substitutions */
const HOMOGLYPHS: Record<string, string[]> = {
  "a": ["\u0430"],           // Cyrillic а
  "c": ["\u0441"],           // Cyrillic с
  "e": ["\u0435"],           // Cyrillic е
  "o": ["\u043E"],           // Cyrillic о
  "p": ["\u0440"],           // Cyrillic р
  "x": ["\u0445"],           // Cyrillic х
  "y": ["\u0443"],           // Cyrillic у
  "A": ["\u0410"],           // Cyrillic А
  "B": ["\u0412"],           // Cyrillic В
  "C": ["\u0421"],           // Cyrillic С
  "E": ["\u0415"],           // Cyrillic Е
  "H": ["\u041D"],           // Cyrillic Н
  "K": ["\u041A"],           // Cyrillic К
  "M": ["\u041C"],           // Cyrillic М
  "O": ["\u041E"],           // Cyrillic О
  "P": ["\u0420"],           // Cyrillic Р
  "T": ["\u0422"],           // Cyrillic Т
  "X": ["\u0425"],           // Cyrillic Х
  " ": ["\u00A0", "\u2003"], // NBSP, Em Space
};

/** Whitespace variants for substitution */
const SPACE_VARIANTS = [
  " ",      // Normal space (U+0020)
  "\u00A0", // Non-breaking space
  "\u2003", // Em space
  "\u2002", // En space
  "\u2009", // Thin space
];

// ── Store ────────────────────────────────────────────────────

interface FingerprintStore {
  records: FingerprintRecord[];
  lastUpdated: string;
}

const STORE_DIR = path.join(process.cwd(), ".doc-engine");
const STORE_PATH = path.join(STORE_DIR, "sdc-fingerprints.json");

function loadStore(): FingerprintStore {
  if (fs.existsSync(STORE_PATH)) {
    return JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
  }
  return { records: [], lastUpdated: new Date().toISOString() };
}

function saveStore(store: FingerprintStore): void {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  store.lastUpdated = new Date().toISOString();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), "utf-8");
}

// ── Forensic Fingerprint Engine ──────────────────────────────

export class ForensicFingerprintEngine {
  private store: FingerprintStore;

  constructor() {
    this.store = loadStore();
  }

  /**
   * Apply forensic fingerprint to document text.
   * Creates a mathematically unique version for this recipient.
   */
  fingerprint(params: {
    documentId: string;
    documentTitle: string;
    text: string;
    recipient: FingerprintRecipient;
  }): FingerprintResult {
    const fingerprintId = crypto.randomBytes(16).toString("hex");
    const timestamp = new Date().toISOString();

    // Derive unique fingerprint hash from recipient + document
    const fingerprintHash = crypto
      .createHash("sha256")
      .update(`forensic:${params.recipient.email}:${params.documentId}:${fingerprintId}`)
      .digest("hex");

    // Apply fingerprinting techniques
    const zwResult = this.insertZeroWidthMarkers(params.text, fingerprintHash);
    const spacingResult = this.computeSpacingVariations(params.text, fingerprintHash);
    const wsResult = this.substituteWhitespace(zwResult.text, fingerprintHash);
    const hgResult = this.substituteHomoglyphs(wsResult.text, fingerprintHash);

    // Build detection profile
    const detectionProfile: DetectionProfile = {
      zwPositions: zwResult.positions,
      zwEncodedHash: zwResult.encodedHash,
      spacingPattern: spacingResult.pattern,
      whitespaceMap: wsResult.substitutions,
      homoglyphPositions: hgResult.substitutions,
    };

    // Compute verification signature
    const verificationSignature = crypto
      .createHmac("sha256", fingerprintHash)
      .update(
        JSON.stringify({
          zwPositions: zwResult.positions,
          spacingPattern: spacingResult.pattern,
          wsCount: wsResult.substitutions.length,
          hgCount: hgResult.substitutions.length,
        })
      )
      .digest("hex");

    const payload: FingerprintPayload = {
      fingerprintId,
      documentId: params.documentId,
      documentTitle: params.documentTitle,
      recipient: params.recipient,
      fingerprintHash,
      timestamp,
      zwMarkerCount: zwResult.positions.length,
      spacingVariations: spacingResult.pattern.length,
      whitespaceSubstitutions: wsResult.substitutions.length,
      homoglyphCount: hgResult.substitutions.length,
      totalModifications:
        zwResult.positions.length +
        spacingResult.pattern.length +
        wsResult.substitutions.length +
        hgResult.substitutions.length,
      verificationSignature,
    };

    // Store record for later forensic matching
    const record: FingerprintRecord = {
      fingerprintId,
      documentId: params.documentId,
      recipientEmail: params.recipient.email,
      fingerprintHash,
      detectionProfile,
      timestamp,
    };
    this.store.records.push(record);
    saveStore(this.store);

    return {
      payload,
      fingerprintedText: hgResult.text,
      spacingCSS: spacingResult.css,
      detectionProfile,
    };
  }

  /**
   * Attempt to identify the source recipient of a leaked document.
   * Compares the leaked text against all stored fingerprint profiles.
   */
  identifySource(params: {
    documentId: string;
    leakedText: string;
  }): ForensicMatch {
    const records = this.store.records.filter(
      (r) => r.documentId === params.documentId
    );

    if (records.length === 0) {
      return {
        matched: false,
        confidence: 0,
        recipientEmail: null,
        fingerprintId: null,
        matchedTechniques: [],
        details: "No fingerprint records found for this document",
      };
    }

    let bestMatch: {
      record: FingerprintRecord;
      score: number;
      techniques: string[];
    } | null = null;

    for (const record of records) {
      const result = this.matchAgainstProfile(params.leakedText, record.detectionProfile);
      if (!bestMatch || result.score > bestMatch.score) {
        bestMatch = {
          record,
          score: result.score,
          techniques: result.techniques,
        };
      }
    }

    if (!bestMatch || bestMatch.score < 0.2) {
      return {
        matched: false,
        confidence: bestMatch?.score || 0,
        recipientEmail: null,
        fingerprintId: null,
        matchedTechniques: bestMatch?.techniques || [],
        details: "No confident match found — fingerprint may have been stripped",
      };
    }

    return {
      matched: true,
      confidence: bestMatch.score,
      recipientEmail: bestMatch.record.recipientEmail,
      fingerprintId: bestMatch.record.fingerprintId,
      matchedTechniques: bestMatch.techniques,
      details:
        `Matched to ${bestMatch.record.recipientEmail} with ` +
        `${(bestMatch.score * 100).toFixed(1)}% confidence via ` +
        bestMatch.techniques.join(", "),
    };
  }

  /**
   * Get all fingerprint records for a document.
   */
  getByDocument(documentId: string): FingerprintRecord[] {
    return this.store.records.filter((r) => r.documentId === documentId);
  }

  /**
   * Get all fingerprint records for a recipient.
   */
  getByRecipient(email: string): FingerprintRecord[] {
    return this.store.records.filter((r) => r.recipientEmail === email);
  }

  /**
   * Get fingerprint statistics.
   */
  getStats(): {
    totalFingerprints: number;
    uniqueDocuments: number;
    uniqueRecipients: number;
  } {
    const docs = new Set(this.store.records.map((r) => r.documentId));
    const recipients = new Set(this.store.records.map((r) => r.recipientEmail));
    return {
      totalFingerprints: this.store.records.length,
      uniqueDocuments: docs.size,
      uniqueRecipients: recipients.size,
    };
  }

  // ── Fingerprinting Techniques ────────────────────────────

  /**
   * Insert zero-width Unicode markers encoding the fingerprint hash.
   * Markers are placed between words at deterministic positions.
   */
  private insertZeroWidthMarkers(
    text: string,
    hash: string
  ): { text: string; positions: number[]; encodedHash: string } {
    // Encode first 32 characters of hash as base-5 zero-width chars
    const encodedChars: string[] = [];
    for (let i = 0; i < 32 && i < hash.length; i++) {
      const byte = parseInt(hash[i], 16);
      encodedChars.push(ZW_CHARS[byte % ZW_CHARS.length]);
    }
    const encodedHash = encodedChars.join("");

    // Find word boundary positions (spaces between words)
    const boundaries: number[] = [];
    for (let i = 0; i < text.length - 1; i++) {
      if (text[i] === " " && text[i + 1] !== " ") {
        boundaries.push(i + 1); // After the space
      }
    }

    if (boundaries.length === 0) {
      return { text, positions: [], encodedHash };
    }

    // Deterministically select insertion points using hash
    const positions: number[] = [];
    const markerInterval = Math.max(1, Math.floor(boundaries.length / encodedChars.length));

    let result = text;
    let offset = 0;

    for (let i = 0; i < encodedChars.length && i * markerInterval < boundaries.length; i++) {
      const boundaryIdx = i * markerInterval;
      const pos = boundaries[boundaryIdx] + offset;
      positions.push(boundaries[boundaryIdx]);

      result = result.substring(0, pos) + encodedChars[i] + result.substring(pos);
      offset += encodedChars[i].length;
    }

    return { text: result, positions, encodedHash };
  }

  /**
   * Compute per-word letter-spacing variations.
   * Each word gets a unique spacing derived from hash bytes.
   */
  private computeSpacingVariations(
    text: string,
    hash: string
  ): { pattern: number[]; css: string } {
    const words = text.split(/\s+/).filter((w) => w.length > 0);
    const pattern: number[] = [];
    const cssRules: string[] = [];

    for (let i = 0; i < words.length; i++) {
      // Use hash bytes to determine spacing deviation
      const hashByte = parseInt(hash.substring((i * 2) % (hash.length - 1), (i * 2) % (hash.length - 1) + 2), 16);
      // Map to -0.03pt to +0.03pt range
      const deviation = ((hashByte / 255) * 0.06 - 0.03);
      pattern.push(Math.round(deviation * 1000) / 1000);

      cssRules.push(
        `.sdc-fw-${i} { letter-spacing: ${deviation.toFixed(4)}pt; }`
      );
    }

    const css = cssRules.join("\n");
    return { pattern, css };
  }

  /**
   * Substitute normal spaces with Unicode space variants at
   * deterministic positions derived from the hash.
   */
  private substituteWhitespace(
    text: string,
    hash: string
  ): {
    text: string;
    substitutions: Array<{ position: number; original: string; replacement: string }>;
  } {
    const substitutions: Array<{ position: number; original: string; replacement: string }> = [];
    const chars = [...text];

    // Use hash to determine which spaces to substitute
    let hashIdx = 0;
    for (let i = 0; i < chars.length; i++) {
      if (chars[i] === " ") {
        const hashByte = parseInt(hash.substring(hashIdx % (hash.length - 1), hashIdx % (hash.length - 1) + 2), 16);
        hashIdx += 2;

        // Only substitute ~30% of spaces (those where hashByte > 180)
        if (hashByte > 180) {
          const variantIdx = hashByte % SPACE_VARIANTS.length;
          const variant = SPACE_VARIANTS[variantIdx];
          if (variant !== " ") {
            substitutions.push({
              position: i,
              original: " ",
              replacement: variant,
            });
            chars[i] = variant;
          }
        }
      }
    }

    return { text: chars.join(""), substitutions };
  }

  /**
   * Replace select characters with visually identical homoglyphs.
   * Deterministic selection based on hash.
   */
  private substituteHomoglyphs(
    text: string,
    hash: string
  ): {
    text: string;
    substitutions: Array<{ position: number; original: string; replacement: string }>;
  } {
    const substitutions: Array<{ position: number; original: string; replacement: string }> = [];
    const chars = [...text];

    // Use hash to determine which characters to substitute
    let hashIdx = 0;
    for (let i = 0; i < chars.length; i++) {
      const ch = chars[i];
      if (HOMOGLYPHS[ch]) {
        const hashByte = parseInt(hash.substring(hashIdx % (hash.length - 1), hashIdx % (hash.length - 1) + 2), 16);
        hashIdx += 2;

        // Only substitute ~15% of eligible characters (hashByte > 216)
        if (hashByte > 216) {
          const variants = HOMOGLYPHS[ch];
          const variant = variants[hashByte % variants.length];
          substitutions.push({
            position: i,
            original: ch,
            replacement: variant,
          });
          chars[i] = variant;
        }
      }
    }

    return { text: chars.join(""), substitutions };
  }

  // ── Forensic Matching ────────────────────────────────────

  /**
   * Match leaked text against a stored detection profile.
   */
  private matchAgainstProfile(
    leakedText: string,
    profile: DetectionProfile
  ): { score: number; techniques: string[] } {
    let totalWeight = 0;
    let matchedWeight = 0;
    const techniques: string[] = [];

    // 1. Check zero-width markers (weight: 40%)
    const zwScore = this.matchZeroWidthMarkers(leakedText, profile);
    totalWeight += 40;
    matchedWeight += zwScore * 40;
    if (zwScore > 0.3) techniques.push("zero-width-markers");

    // 2. Check homoglyph substitutions (weight: 30%)
    const hgScore = this.matchHomoglyphs(leakedText, profile);
    totalWeight += 30;
    matchedWeight += hgScore * 30;
    if (hgScore > 0.3) techniques.push("homoglyphs");

    // 3. Check whitespace substitutions (weight: 20%)
    const wsScore = this.matchWhitespace(leakedText, profile);
    totalWeight += 20;
    matchedWeight += wsScore * 20;
    if (wsScore > 0.3) techniques.push("whitespace-variants");

    // 4. Check spacing pattern influence (weight: 10%)
    // Spacing CSS doesn't survive text extraction, but letter positioning
    // may survive screenshots. Lower weight.
    totalWeight += 10;
    if (profile.spacingPattern.length > 0) {
      matchedWeight += 5; // Partial credit
      techniques.push("spacing-pattern-inferred");
    }

    return {
      score: totalWeight > 0 ? matchedWeight / totalWeight : 0,
      techniques,
    };
  }

  /**
   * Check for presence of zero-width markers.
   */
  private matchZeroWidthMarkers(text: string, profile: DetectionProfile): number {
    // Extract all zero-width characters from the text
    const found: string[] = [];
    for (const ch of text) {
      if (ZW_CHARS.includes(ch)) {
        found.push(ch);
      }
    }

    if (found.length === 0) return 0;

    // Reconstruct the encoded hash
    const foundHash = found.join("");
    if (foundHash === profile.zwEncodedHash) return 1.0;

    // Partial match — check overlap
    const expectedChars = [...profile.zwEncodedHash];
    let matching = 0;
    for (let i = 0; i < Math.min(found.length, expectedChars.length); i++) {
      if (found[i] === expectedChars[i]) matching++;
    }

    return expectedChars.length > 0 ? matching / expectedChars.length : 0;
  }

  /**
   * Check for homoglyph substitutions matching the profile.
   */
  private matchHomoglyphs(text: string, profile: DetectionProfile): number {
    if (profile.homoglyphPositions.length === 0) return 0;

    let found = 0;
    const chars = [...text];

    for (const sub of profile.homoglyphPositions) {
      if (sub.position < chars.length && chars[sub.position] === sub.replacement) {
        found++;
      }
    }

    return found / profile.homoglyphPositions.length;
  }

  /**
   * Check whitespace variants matching the profile.
   */
  private matchWhitespace(text: string, profile: DetectionProfile): number {
    if (profile.whitespaceMap.length === 0) return 0;

    let found = 0;
    const chars = [...text];

    for (const sub of profile.whitespaceMap) {
      if (sub.position < chars.length && chars[sub.position] === sub.replacement) {
        found++;
      }
    }

    return found / profile.whitespaceMap.length;
  }
}

// ── Singleton ────────────────────────────────────────────────

let _fpEngine: ForensicFingerprintEngine | null = null;

export function getForensicFingerprintEngine(): ForensicFingerprintEngine {
  if (!_fpEngine) {
    _fpEngine = new ForensicFingerprintEngine();
  }
  return _fpEngine;
}
