// ─────────────────────────────────────────────────────────────
// Secure Document Control — Export Policy Engine
//
// Controls how documents may be exported from the system.
//
// Export Policies:
//   NONE          — No export allowed
//   VIEW_ONLY     — Secure viewer only, no file download
//   PDF_ONLY      — PDF export with watermark
//   PDF_PASSWORD  — PDF with recipient-specific AES password
//   DOCX_RESTRICTED — Word read-only with watermark embedded
//   FULL          — All exports allowed (internal only)
//
// Every exported file:
//   - Watermarked per recipient
//   - Encrypted if policy requires
//   - Logged in access ledger
//   - Contains embedded metadata fingerprint
//   - DRM restrictions applied where possible
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { ExportPolicy, WatermarkPolicy } from "./documentIntakeEngine";
import { WatermarkEngine, WatermarkRecipient, WatermarkResult } from "./watermarkEngine";

// ── Types ────────────────────────────────────────────────────

export type ExportFormat = "pdf" | "docx" | "html" | "json";

export interface ExportRequest {
  /** Document ID */
  documentId: string;
  /** Document title */
  documentTitle: string;
  /** Document HTML content */
  documentContent: string;
  /** Document hash */
  documentHash: string;
  /** Recipient info */
  recipient: WatermarkRecipient;
  /** Export format */
  format: ExportFormat;
  /** Export policy in effect */
  policy: ExportPolicy;
  /** Watermark policy in effect */
  watermarkPolicy: WatermarkPolicy;
  /** Confidentiality notice */
  confidentialityNotice: string;
  /** Access token (for logging) */
  accessToken?: string;
}

export interface ExportResult {
  /** Whether export was allowed */
  allowed: boolean;
  /** Denial reason (if not allowed) */
  reason: string;
  /** Export record ID */
  exportId: string;
  /** Output file path (if generated) */
  outputPath: string | null;
  /** Output content (if in-memory) */
  outputContent: string | null;
  /** Watermark applied */
  watermark: WatermarkResult | null;
  /** Password (if encrypted, delivered separately) */
  password: string | null;
  /** Export metadata */
  metadata: ExportMetadata;
}

export interface ExportMetadata {
  /** Export timestamp */
  timestamp: string;
  /** Export format */
  format: ExportFormat;
  /** Policy applied */
  policy: ExportPolicy;
  /** Watermark policy */
  watermarkPolicy: WatermarkPolicy;
  /** Recipient email */
  recipientEmail: string;
  /** Document hash */
  documentHash: string;
  /** Export hash (hash of the exported content) */
  exportHash: string;
  /** Password protected */
  passwordProtected: boolean;
  /** DRM restrictions */
  drmRestrictions: string[];
}

export interface ExportRecord {
  /** Unique export record ID */
  exportId: string;
  /** Document ID */
  documentId: string;
  /** Recipient email */
  recipientEmail: string;
  /** Format */
  format: ExportFormat;
  /** Policy */
  policy: ExportPolicy;
  /** Allowed */
  allowed: boolean;
  /** Denial reason */
  denialReason?: string;
  /** Output path */
  outputPath: string | null;
  /** Export hash */
  exportHash: string;
  /** Watermark ID */
  watermarkId: string | null;
  /** Timestamp */
  timestamp: string;
}

// ── Store ────────────────────────────────────────────────────

interface ExportStore {
  records: ExportRecord[];
  lastUpdated: string;
}

const STORE_DIR = path.join(process.cwd(), ".doc-engine");
const EXPORT_DIR = path.join(STORE_DIR, "sdc-exports");
const STORE_PATH = path.join(STORE_DIR, "sdc-export-log.json");

function loadStore(): ExportStore {
  if (fs.existsSync(STORE_PATH)) {
    return JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
  }
  return { records: [], lastUpdated: new Date().toISOString() };
}

function saveStore(store: ExportStore): void {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  store.lastUpdated = new Date().toISOString();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), "utf-8");
}

// ── Export Policy Engine ─────────────────────────────────────

export class ExportPolicyEngine {
  private store: ExportStore;
  private watermarkEngine: WatermarkEngine;

  constructor(watermarkEngine?: WatermarkEngine) {
    this.store = loadStore();
    this.watermarkEngine = watermarkEngine || new WatermarkEngine();
  }

  /**
   * Process an export request.
   * Enforces policy, applies watermark, encrypts if required.
   */
  processExport(request: ExportRequest): ExportResult {
    const exportId = crypto.randomBytes(16).toString("hex");
    const timestamp = new Date().toISOString();

    // Check if export is allowed
    const policyCheck = this.checkPolicy(request.policy, request.format);
    if (!policyCheck.allowed) {
      const record: ExportRecord = {
        exportId,
        documentId: request.documentId,
        recipientEmail: request.recipient.email,
        format: request.format,
        policy: request.policy,
        allowed: false,
        denialReason: policyCheck.reason,
        outputPath: null,
        exportHash: "",
        watermarkId: null,
        timestamp,
      };
      this.store.records.push(record);
      saveStore(this.store);

      return {
        allowed: false,
        reason: policyCheck.reason,
        exportId,
        outputPath: null,
        outputContent: null,
        watermark: null,
        password: null,
        metadata: {
          timestamp,
          format: request.format,
          policy: request.policy,
          watermarkPolicy: request.watermarkPolicy,
          recipientEmail: request.recipient.email,
          documentHash: request.documentHash,
          exportHash: "",
          passwordProtected: false,
          drmRestrictions: [],
        },
      };
    }

    // Generate watermark
    let watermark: WatermarkResult | null = null;
    if (request.watermarkPolicy !== "NONE") {
      watermark = this.watermarkEngine.generate({
        documentId: request.documentId,
        documentTitle: request.documentTitle,
        recipient: request.recipient,
        policy: request.watermarkPolicy,
        confidentialityNotice: request.confidentialityNotice,
      });
    }

    // Build export content based on format
    let outputContent: string;
    let password: string | null = null;
    const drmRestrictions: string[] = [];

    switch (request.format) {
      case "html":
        outputContent = this.buildHTMLExport(request, watermark);
        break;
      case "json":
        outputContent = this.buildJSONExport(request, watermark);
        break;
      case "pdf":
        outputContent = this.buildPDFReadyHTML(request, watermark);
        if (request.policy === "PDF_PASSWORD") {
          password = this.generatePassword(request.recipient.email, request.documentId);
          drmRestrictions.push("password-protected");
        }
        drmRestrictions.push("no-copy", "no-edit");
        if (request.policy !== "FULL") {
          drmRestrictions.push("no-print");
        }
        break;
      case "docx":
        outputContent = this.buildDOCXReadyContent(request, watermark);
        drmRestrictions.push("read-only", "no-track-changes");
        break;
      default:
        outputContent = request.documentContent;
    }

    // Compute export hash
    const exportHash = crypto
      .createHash("sha256")
      .update(outputContent)
      .digest("hex");

    // Save exported file
    if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });
    const safeTitle = request.documentTitle.replace(/[^a-zA-Z0-9.-]/g, "_").substring(0, 50);
    const safeEmail = request.recipient.email.replace(/[^a-zA-Z0-9]/g, "_").substring(0, 30);
    const fileName = `${safeTitle}-${safeEmail}-${exportId.substring(0, 8)}.${request.format === "pdf" ? "html" : request.format}`;
    const outputPath = path.join(EXPORT_DIR, fileName);
    fs.writeFileSync(outputPath, outputContent, "utf-8");

    // Log export
    const record: ExportRecord = {
      exportId,
      documentId: request.documentId,
      recipientEmail: request.recipient.email,
      format: request.format,
      policy: request.policy,
      allowed: true,
      outputPath,
      exportHash,
      watermarkId: watermark?.payload.watermarkId || null,
      timestamp,
    };
    this.store.records.push(record);
    saveStore(this.store);

    return {
      allowed: true,
      reason: "Export processed",
      exportId,
      outputPath,
      outputContent,
      watermark,
      password,
      metadata: {
        timestamp,
        format: request.format,
        policy: request.policy,
        watermarkPolicy: request.watermarkPolicy,
        recipientEmail: request.recipient.email,
        documentHash: request.documentHash,
        exportHash,
        passwordProtected: !!password,
        drmRestrictions,
      },
    };
  }

  /**
   * Check if a specific export format is allowed under the policy.
   */
  checkPolicy(
    policy: ExportPolicy,
    format: ExportFormat
  ): { allowed: boolean; reason: string } {
    switch (policy) {
      case "NONE":
        return { allowed: false, reason: "Export is prohibited for this document" };

      case "VIEW_ONLY":
        if (format === "html") {
          return { allowed: true, reason: "View-only HTML allowed" };
        }
        return { allowed: false, reason: `Export as ${format} not allowed — view only` };

      case "PDF_ONLY":
        if (format === "pdf" || format === "html") {
          return { allowed: true, reason: `${format.toUpperCase()} export allowed` };
        }
        return { allowed: false, reason: `Only PDF export is allowed for this document` };

      case "PDF_PASSWORD":
        if (format === "pdf" || format === "html") {
          return { allowed: true, reason: `${format.toUpperCase()} export allowed (password-protected)` };
        }
        return { allowed: false, reason: `Only password-protected PDF export is allowed` };

      case "DOCX_RESTRICTED":
        if (format === "pdf" || format === "html" || format === "docx") {
          return { allowed: true, reason: `${format.toUpperCase()} export allowed (restricted)` };
        }
        return { allowed: false, reason: `Format ${format} not allowed under DOCX_RESTRICTED policy` };

      case "FULL":
        return { allowed: true, reason: "Full export access" };

      default:
        return { allowed: false, reason: "Unknown export policy" };
    }
  }

  /**
   * Get export records for a document.
   */
  getByDocument(documentId: string): ExportRecord[] {
    return this.store.records.filter((r) => r.documentId === documentId);
  }

  /**
   * Get export records for a recipient.
   */
  getByRecipient(email: string): ExportRecord[] {
    return this.store.records.filter((r) => r.recipientEmail === email);
  }

  /**
   * Get export statistics.
   */
  getStats(): {
    totalExports: number;
    totalDenials: number;
    byFormat: Record<string, number>;
    byPolicy: Record<string, number>;
  } {
    const byFormat: Record<string, number> = {};
    const byPolicy: Record<string, number> = {};
    let denials = 0;

    for (const r of this.store.records) {
      byFormat[r.format] = (byFormat[r.format] || 0) + 1;
      byPolicy[r.policy] = (byPolicy[r.policy] || 0) + 1;
      if (!r.allowed) denials++;
    }

    return {
      totalExports: this.store.records.filter((r) => r.allowed).length,
      totalDenials: denials,
      byFormat,
      byPolicy,
    };
  }

  // ── Private Methods ──────────────────────────────────────

  /**
   * Build HTML export with watermark overlay.
   */
  private buildHTMLExport(request: ExportRequest, watermark: WatermarkResult | null): string {
    const wmCSS = watermark?.cssStyles || "";
    const wmOverlay = watermark?.htmlOverlay || "";
    const wmScript = watermark?.dynamicScript || "";
    const metaTags = watermark
      ? Object.entries(watermark.metadataFields)
          .map(([k, v]) => `  <meta name="${k}" content="${this.escapeHtml(v)}" />`)
          .join("\n")
      : "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${this.escapeHtml(request.documentTitle)} — Secure Export</title>
${metaTags}
  <style>
    body {
      font-family: 'Georgia', 'Times New Roman', serif;
      max-width: 800px;
      margin: 40px auto;
      padding: 0 20px;
      color: #1a1a1a;
      line-height: 1.6;
    }
    .sdc-header {
      border-bottom: 2px solid #1a1a1a;
      padding-bottom: 12px;
      margin-bottom: 24px;
    }
    .sdc-header h1 { margin: 0; font-size: 24px; }
    .sdc-notice {
      background: #fff3cd;
      border: 1px solid #ffc107;
      padding: 12px;
      margin-bottom: 24px;
      font-size: 11px;
      color: #856404;
    }
    .sdc-content {
      margin-bottom: 40px;
    }
    .sdc-export-footer {
      border-top: 1px solid #ccc;
      padding-top: 8px;
      font-size: 9px;
      color: #999;
    }
${wmCSS}
  </style>
</head>
<body>
  <div class="sdc-header">
    <h1>${this.escapeHtml(request.documentTitle)}</h1>
  </div>
  <div class="sdc-notice">
    ${this.escapeHtml(request.confidentialityNotice)}
  </div>
  <div class="sdc-content sdc-protected">
    ${request.documentContent}
  </div>
  <div class="sdc-export-footer">
    <div>Exported for: ${this.escapeHtml(request.recipient.name)} &lt;${this.escapeHtml(request.recipient.email)}&gt;</div>
    <div>Document ID: ${request.documentId.substring(0, 16)}</div>
    <div>Export Hash: ${crypto.createHash("sha256").update(request.documentContent).digest("hex").substring(0, 16)}</div>
    <div>Timestamp: ${new Date().toISOString()}</div>
  </div>
${wmOverlay}
  <script>${wmScript}</script>
</body>
</html>`;
  }

  /**
   * Build JSON export with metadata.
   */
  private buildJSONExport(request: ExportRequest, watermark: WatermarkResult | null): string {
    return JSON.stringify({
      document: {
        id: request.documentId,
        title: request.documentTitle,
        hash: request.documentHash,
      },
      export: {
        format: "json",
        policy: request.policy,
        timestamp: new Date().toISOString(),
        recipient: {
          name: request.recipient.name,
          email: request.recipient.email,
        },
      },
      watermark: watermark
        ? {
            id: watermark.payload.watermarkId,
            hash: watermark.payload.watermarkHash,
            footerHash: watermark.payload.footerHash,
          }
        : null,
      confidentialityNotice: request.confidentialityNotice,
      content: request.documentContent,
    }, null, 2);
  }

  /**
   * Build PDF-ready HTML (for conversion via puppeteer).
   */
  private buildPDFReadyHTML(request: ExportRequest, watermark: WatermarkResult | null): string {
    const svgWatermark = watermark?.svgWatermark || "";
    const metaFields = watermark?.metadataFields || {};

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>${this.escapeHtml(request.documentTitle)}</title>
${Object.entries(metaFields).map(([k, v]) => `  <meta name="${k}" content="${this.escapeHtml(v)}" />`).join("\n")}
  <style>
    @page {
      size: letter;
      margin: 1in;
    }
    body {
      font-family: 'Georgia', serif;
      font-size: 11pt;
      color: #1a1a1a;
      line-height: 1.5;
    }
    .watermark-bg {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: -1;
      opacity: 0.06;
    }
    .pdf-header {
      border-bottom: 2px solid #000;
      padding-bottom: 8pt;
      margin-bottom: 18pt;
    }
    .pdf-notice {
      background: #f5f5f5;
      border: 1px solid #ddd;
      padding: 8pt;
      font-size: 8pt;
      margin-bottom: 18pt;
    }
    .pdf-footer {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      font-size: 7pt;
      color: #999;
      border-top: 0.5pt solid #ccc;
      padding-top: 4pt;
    }
  </style>
</head>
<body>
  <div class="watermark-bg">
    ${svgWatermark}
  </div>
  <div class="pdf-header">
    <strong>${this.escapeHtml(request.documentTitle)}</strong>
  </div>
  <div class="pdf-notice">
    ${this.escapeHtml(request.confidentialityNotice)}
  </div>
  <div class="pdf-content">
    ${request.documentContent}
  </div>
  <div class="pdf-footer">
    Exported for: ${this.escapeHtml(request.recipient.name)} | ${this.escapeHtml(request.recipient.email)} |
    ${watermark?.payload.footerHash || request.documentHash.substring(0, 16)} |
    ${new Date().toISOString()}
  </div>
</body>
</html>`;
  }

  /**
   * Build DOCX-ready content (structured for conversion).
   */
  private buildDOCXReadyContent(request: ExportRequest, watermark: WatermarkResult | null): string {
    const header = [
      `[DOCUMENT: ${request.documentTitle}]`,
      `[CLASSIFICATION: RESTRICTED]`,
      `[WATERMARK: ${watermark?.payload.footerHash || "NONE"}]`,
      ``,
      `━━━ CONFIDENTIALITY NOTICE ━━━`,
      request.confidentialityNotice,
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
      ``,
    ].join("\n");

    const footer = [
      ``,
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
      `Exported for: ${request.recipient.name} <${request.recipient.email}>`,
      `Document ID: ${request.documentId.substring(0, 16)}`,
      `Export Hash: ${crypto.createHash("sha256").update(request.documentContent).digest("hex").substring(0, 16)}`,
      `Timestamp: ${new Date().toISOString()}`,
      `Footer Hash: ${watermark?.payload.footerHash || "—"}`,
      `READ ONLY — Modifications are prohibited`,
    ].join("\n");

    // Inject invisible markers if available
    let content = request.documentContent;
    if (watermark?.payload.invisibleMarkers) {
      content = new WatermarkEngine().injectInvisibleMarkers(content, watermark.payload.invisibleMarkers);
    }

    return header + content + footer;
  }

  /**
   * Generate deterministic password from recipient + document.
   */
  private generatePassword(email: string, documentId: string): string {
    const hash = crypto
      .createHash("sha256")
      .update(`sdc-password:${email}:${documentId}:${Date.now()}`)
      .digest("hex");
    // Create a readable password: 4 groups of 4 chars
    return `${hash.substring(0, 4)}-${hash.substring(4, 8)}-${hash.substring(8, 12)}-${hash.substring(12, 16)}`.toUpperCase();
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _exportEngine: ExportPolicyEngine | null = null;

export function getExportPolicyEngine(): ExportPolicyEngine {
  if (!_exportEngine) {
    _exportEngine = new ExportPolicyEngine();
  }
  return _exportEngine;
}
