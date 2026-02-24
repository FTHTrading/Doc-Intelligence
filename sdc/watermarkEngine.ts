// ─────────────────────────────────────────────────────────────
// Secure Document Control — Watermark Engine
//
// Per-recipient watermarking at three levels:
//
//   STANDARD:  Visible diagonal text + footer hash string
//   FORENSIC:  Standard + invisible Unicode markers
//   MAXIMUM:   Forensic + micro spacing variations
//
// Every exported document is watermarked uniquely per recipient.
// If leaked → the watermark identifies who leaked it.
//
// Watermark payload:
//   Recipient Name, Email, IP, Timestamp,
//   Access Token, Document ID, Confidentiality Notice
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import { WatermarkPolicy } from "./documentIntakeEngine";

// ── Types ────────────────────────────────────────────────────

export interface WatermarkRecipient {
  /** Recipient name */
  name: string;
  /** Recipient email */
  email: string;
  /** Recipient IP address */
  ip: string;
  /** Access token */
  accessToken: string;
  /** Organization (optional) */
  organization?: string;
}

export interface WatermarkPayload {
  /** Unique watermark ID */
  watermarkId: string;
  /** Document ID */
  documentId: string;
  /** Document title */
  documentTitle: string;
  /** Recipient info */
  recipient: WatermarkRecipient;
  /** Timestamp */
  timestamp: string;
  /** Watermark policy level */
  policy: WatermarkPolicy;
  /** Watermark hash (unique fingerprint of this specific copy) */
  watermarkHash: string;
  /** Visible watermark text (diagonal) */
  visibleText: string;
  /** Footer hash string */
  footerHash: string;
  /** Invisible Unicode markers (for FORENSIC+) */
  invisibleMarkers?: string;
  /** Micro spacing pattern (for MAXIMUM) */
  spacingPattern?: number[];
  /** Confidentiality notice */
  confidentialityNotice: string;
}

export interface WatermarkResult {
  /** The watermark payload */
  payload: WatermarkPayload;
  /** HTML watermark overlay (CSS positioned) */
  htmlOverlay: string;
  /** CSS styles for the watermark */
  cssStyles: string;
  /** JavaScript for dynamic watermarking */
  dynamicScript: string;
  /** SVG watermark for PDF embedding */
  svgWatermark: string;
  /** Metadata fields to embed in document */
  metadataFields: Record<string, string>;
}

// ── Invisible Unicode Characters ─────────────────────────────

// Zero-width characters used for invisible fingerprinting
const ZERO_WIDTH_CHARS = [
  "\u200B", // Zero-width space
  "\u200C", // Zero-width non-joiner
  "\u200D", // Zero-width joiner
  "\u2060", // Word joiner
  "\uFEFF", // Zero-width no-break space
];

// ── Watermark Engine ─────────────────────────────────────────

export class WatermarkEngine {
  /**
   * Generate a complete watermark package for a specific recipient.
   */
  generate(params: {
    documentId: string;
    documentTitle: string;
    recipient: WatermarkRecipient;
    policy: WatermarkPolicy;
    confidentialityNotice: string;
  }): WatermarkResult {
    const watermarkId = crypto.randomBytes(16).toString("hex");
    const timestamp = new Date().toISOString();

    // Compute unique watermark hash
    const watermarkHash = this.computeWatermarkHash(
      watermarkId,
      params.documentId,
      params.recipient.email,
      params.recipient.ip,
      timestamp
    );

    // Visible watermark text
    const visibleText = this.buildVisibleText(params.recipient, timestamp);

    // Footer hash string
    const footerHash = `SDC-${watermarkHash.substring(0, 8).toUpperCase()}-${params.documentId.substring(0, 8).toUpperCase()}`;

    // Build payload
    const payload: WatermarkPayload = {
      watermarkId,
      documentId: params.documentId,
      documentTitle: params.documentTitle,
      recipient: params.recipient,
      timestamp,
      policy: params.policy,
      watermarkHash,
      visibleText,
      footerHash,
      confidentialityNotice: params.confidentialityNotice,
    };

    // Add forensic markers if policy requires
    if (params.policy === "FORENSIC" || params.policy === "MAXIMUM") {
      payload.invisibleMarkers = this.generateInvisibleMarkers(watermarkHash);
    }

    // Add spacing pattern if MAXIMUM
    if (params.policy === "MAXIMUM") {
      payload.spacingPattern = this.generateSpacingPattern(watermarkHash);
    }

    // Generate visual assets
    const htmlOverlay = this.generateHTMLOverlay(payload);
    const cssStyles = this.generateCSSStyles(payload);
    const dynamicScript = this.generateDynamicScript(payload);
    const svgWatermark = this.generateSVGWatermark(payload);
    const metadataFields = this.generateMetadataFields(payload);

    return {
      payload,
      htmlOverlay,
      cssStyles,
      dynamicScript,
      svgWatermark,
      metadataFields,
    };
  }

  /**
   * Decode invisible markers from text to recover watermark hash.
   */
  decodeInvisibleMarkers(text: string): string | null {
    const markers: string[] = [];
    for (const char of text) {
      const idx = ZERO_WIDTH_CHARS.indexOf(char);
      if (idx !== -1) {
        markers.push(idx.toString());
      }
    }
    if (markers.length === 0) return null;

    // Reconstruct the hex hash from base-5 encoding
    let hex = "";
    for (let i = 0; i < markers.length; i += 2) {
      if (i + 1 < markers.length) {
        const val = parseInt(markers[i]) * 5 + parseInt(markers[i + 1]);
        hex += val.toString(16);
      }
    }
    return hex || null;
  }

  /**
   * Detect spacing pattern in text to identify recipient.
   */
  detectSpacingPattern(spacings: number[]): number[] {
    // Extract the deviation pattern from measured spacings
    return spacings.map((s) => Math.round((s - 1.0) * 10000));
  }

  // ── Private Methods ──────────────────────────────────────

  private computeWatermarkHash(
    watermarkId: string,
    documentId: string,
    email: string,
    ip: string,
    timestamp: string
  ): string {
    return crypto
      .createHash("sha256")
      .update(`${watermarkId}:${documentId}:${email}:${ip}:${timestamp}`)
      .digest("hex");
  }

  private buildVisibleText(recipient: WatermarkRecipient, timestamp: string): string {
    const date = new Date(timestamp);
    const dateStr = date.toISOString().split("T")[0];
    const timeStr = date.toISOString().split("T")[1].substring(0, 8);
    return `CONFIDENTIAL — ${recipient.name} — ${recipient.email} — ${dateStr} ${timeStr}`;
  }

  /**
   * Generate invisible Unicode markers that encode the watermark hash.
   * Uses zero-width characters as a base-5 encoding.
   */
  private generateInvisibleMarkers(watermarkHash: string): string {
    let markers = "";
    // Encode first 16 hex chars (64 bits) into zero-width characters
    const hashPrefix = watermarkHash.substring(0, 16);
    for (const hexChar of hashPrefix) {
      const val = parseInt(hexChar, 16);
      // Encode each hex digit as two base-5 digits
      const high = Math.floor(val / 5);
      const low = val % 5;
      markers += ZERO_WIDTH_CHARS[high];
      markers += ZERO_WIDTH_CHARS[low];
    }
    return markers;
  }

  /**
   * Generate micro spacing pattern from watermark hash.
   * Each value represents a fractional point deviation in letter spacing.
   * The pattern is unique per recipient — forensic analysis can identify the source.
   */
  private generateSpacingPattern(watermarkHash: string): number[] {
    const pattern: number[] = [];
    // Use bytes 16-32 of the hash for spacing
    const spacingPart = watermarkHash.substring(16, 48);
    for (let i = 0; i < spacingPart.length; i += 2) {
      const byte = parseInt(spacingPart.substring(i, i + 2), 16);
      // Convert to subtle spacing variation: -0.03pt to +0.03pt
      const deviation = ((byte / 255) * 0.06) - 0.03;
      pattern.push(Math.round(deviation * 10000) / 10000);
    }
    return pattern;
  }

  /**
   * Generate HTML overlay for web viewing.
   */
  private generateHTMLOverlay(payload: WatermarkPayload): string {
    if (payload.policy === "NONE") return "";

    const lines: string[] = [
      `<div class="sdc-watermark-overlay" data-wm-id="${payload.watermarkId}">`,
      `  <div class="sdc-watermark-diagonal">`,
      `    <span>${this.escapeHtml(payload.visibleText)}</span>`,
      `  </div>`,
      `  <div class="sdc-watermark-footer">`,
      `    <span class="sdc-footer-hash">${payload.footerHash}</span>`,
      `    <span class="sdc-footer-notice">${this.escapeHtml(payload.confidentialityNotice)}</span>`,
      `  </div>`,
    ];

    // Add invisible markers
    if (payload.invisibleMarkers) {
      lines.push(
        `  <span class="sdc-invisible" aria-hidden="true">${payload.invisibleMarkers}</span>`
      );
    }

    // Add dynamic timestamp overlay
    lines.push(
      `  <div class="sdc-watermark-dynamic">`,
      `    <span class="sdc-dynamic-text"></span>`,
      `  </div>`
    );

    lines.push(`</div>`);
    return lines.join("\n");
  }

  /**
   * Generate CSS for watermark display.
   */
  private generateCSSStyles(payload: WatermarkPayload): string {
    if (payload.policy === "NONE") return "";

    return `
.sdc-watermark-overlay {
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  pointer-events: none;
  z-index: 10000;
  overflow: hidden;
}
.sdc-watermark-diagonal {
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%) rotate(-35deg);
  white-space: nowrap;
  font-size: 24px;
  font-family: 'Courier New', monospace;
  color: rgba(200, 0, 0, 0.08);
  letter-spacing: 4px;
  user-select: none;
  -webkit-user-select: none;
}
.sdc-watermark-footer {
  position: fixed;
  bottom: 0; left: 0; right: 0;
  padding: 4px 12px;
  background: rgba(0, 0, 0, 0.03);
  border-top: 1px solid rgba(0, 0, 0, 0.06);
  font-size: 9px;
  font-family: 'Courier New', monospace;
  color: rgba(0, 0, 0, 0.25);
  display: flex;
  justify-content: space-between;
  user-select: none;
  -webkit-user-select: none;
}
.sdc-invisible {
  position: absolute;
  width: 0; height: 0;
  overflow: hidden;
  opacity: 0;
  font-size: 0;
}
.sdc-watermark-dynamic {
  position: fixed;
  top: 10px; right: 10px;
  font-size: 10px;
  font-family: 'Courier New', monospace;
  color: rgba(0, 0, 0, 0.06);
  user-select: none;
  -webkit-user-select: none;
}
/* Anti-copy: prevent text selection on watermarked content */
.sdc-protected {
  -webkit-user-select: none;
  -moz-user-select: none;
  -ms-user-select: none;
  user-select: none;
}
/* Screenshot deterrence: dynamic overlay changes frequently */
@media print {
  .sdc-watermark-diagonal {
    color: rgba(200, 0, 0, 0.15) !important;
    font-size: 36px !important;
  }
  .sdc-watermark-footer {
    color: rgba(0, 0, 0, 0.5) !important;
  }
}
`;
  }

  /**
   * Generate JavaScript for dynamic watermarking.
   * Updates the dynamic overlay every 60 seconds with current timestamp.
   */
  private generateDynamicScript(payload: WatermarkPayload): string {
    if (payload.policy === "NONE") return "";

    return `
(function() {
  var wmId = "${payload.watermarkId}";
  var recipientName = "${this.escapeJs(payload.recipient.name)}";
  var recipientEmail = "${this.escapeJs(payload.recipient.email)}";
  var docId = "${payload.documentId.substring(0, 12)}";

  function updateDynamic() {
    var el = document.querySelector('.sdc-dynamic-text');
    if (!el) return;
    var now = new Date();
    el.textContent = 'Viewing: ' + recipientName + ' | ' +
      recipientEmail + ' | ' +
      now.toISOString().substring(0, 19) + ' | ' +
      docId;
  }

  // Update immediately and every 60s
  updateDynamic();
  setInterval(updateDynamic, 60000);

  // Anti-copy measures
  document.addEventListener('contextmenu', function(e) { e.preventDefault(); });
  document.addEventListener('copy', function(e) {
    e.preventDefault();
    if (e.clipboardData) {
      e.clipboardData.setData('text/plain',
        'COPY BLOCKED — This document is protected by FTH Secure Document Control. ' +
        'Watermark ID: ' + wmId);
    }
  });

  // Print detection
  var printAttempts = 0;
  window.addEventListener('beforeprint', function() {
    printAttempts++;
    console.warn('[SDC] Print attempt detected — watermark enhanced. Attempt #' + printAttempts);
  });

  // Screenshot deterrence: overlay shifts
  document.addEventListener('keydown', function(e) {
    if ((e.key === 'PrintScreen') || (e.ctrlKey && e.key === 'p')) {
      var diag = document.querySelector('.sdc-watermark-diagonal');
      if (diag) {
        diag.style.color = 'rgba(200, 0, 0, 0.25)';
        diag.style.fontSize = '36px';
        setTimeout(function() {
          diag.style.color = 'rgba(200, 0, 0, 0.08)';
          diag.style.fontSize = '24px';
        }, 3000);
      }
    }
  });
})();
`;
  }

  /**
   * Generate SVG watermark for embedding in PDFs.
   */
  private generateSVGWatermark(payload: WatermarkPayload): string {
    if (payload.policy === "NONE") return "";

    const escapedText = this.escapeHtml(payload.visibleText);
    const escapedFooter = this.escapeHtml(payload.footerHash);
    const escapedNotice = this.escapeHtml(
      payload.confidentialityNotice.length > 120
        ? payload.confidentialityNotice.substring(0, 117) + "..."
        : payload.confidentialityNotice
    );

    return `<svg xmlns="http://www.w3.org/2000/svg" width="800" height="1100" viewBox="0 0 800 1100">
  <!-- Diagonal watermark -->
  <text x="400" y="550" font-family="Courier New, monospace" font-size="18"
        fill="rgba(200,0,0,0.08)" text-anchor="middle"
        transform="rotate(-35, 400, 550)">
    ${escapedText}
  </text>
  <!-- Footer hash -->
  <text x="20" y="1080" font-family="Courier New, monospace" font-size="8"
        fill="rgba(0,0,0,0.25)">
    ${escapedFooter}
  </text>
  <!-- Confidentiality notice -->
  <text x="780" y="1080" font-family="Courier New, monospace" font-size="7"
        fill="rgba(0,0,0,0.2)" text-anchor="end">
    ${escapedNotice}
  </text>
  <!-- Invisible metadata (not rendered visually but present in file) -->
  <metadata>
    <sdc:watermark xmlns:sdc="urn:fth:sdc">
      <sdc:id>${payload.watermarkId}</sdc:id>
      <sdc:document>${payload.documentId}</sdc:document>
      <sdc:recipient>${this.escapeHtml(payload.recipient.email)}</sdc:recipient>
      <sdc:hash>${payload.watermarkHash}</sdc:hash>
      <sdc:timestamp>${payload.timestamp}</sdc:timestamp>
    </sdc:watermark>
  </metadata>
</svg>`;
  }

  /**
   * Generate metadata fields for document embedding.
   */
  private generateMetadataFields(payload: WatermarkPayload): Record<string, string> {
    return {
      "sdc-watermark-id": payload.watermarkId,
      "sdc-document-id": payload.documentId,
      "sdc-recipient": payload.recipient.email,
      "sdc-recipient-name": payload.recipient.name,
      "sdc-recipient-ip": payload.recipient.ip,
      "sdc-watermark-hash": payload.watermarkHash,
      "sdc-timestamp": payload.timestamp,
      "sdc-policy": payload.policy,
      "sdc-footer-hash": payload.footerHash,
    };
  }

  /**
   * Inject invisible markers into document text.
   * Spreads zero-width characters throughout the content.
   */
  injectInvisibleMarkers(text: string, markers: string): string {
    if (!markers || markers.length === 0) return text;

    // Distribute markers evenly through the text
    const words = text.split(" ");
    if (words.length === 0) return text;

    const interval = Math.max(1, Math.floor(words.length / markers.length));
    let markerIdx = 0;
    const result: string[] = [];

    for (let i = 0; i < words.length; i++) {
      result.push(words[i]);
      if (markerIdx < markers.length && (i + 1) % interval === 0) {
        result[result.length - 1] += markers[markerIdx];
        markerIdx++;
      }
    }

    return result.join(" ");
  }

  /**
   * Apply micro-spacing pattern to CSS.
   * Returns CSS custom property declarations.
   */
  generateSpacingCSS(pattern: number[]): string {
    if (!pattern || pattern.length === 0) return "";

    const rules: string[] = [];
    for (let i = 0; i < pattern.length; i++) {
      rules.push(`.sdc-spacing-${i} { letter-spacing: ${pattern[i]}em; }`);
    }
    return rules.join("\n");
  }

  // ── Helpers ──────────────────────────────────────────────

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  private escapeJs(text: string): string {
    return text
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/'/g, "\\'")
      .replace(/\n/g, "\\n");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _watermarkEngine: WatermarkEngine | null = null;

export function getWatermarkEngine(): WatermarkEngine {
  if (!_watermarkEngine) {
    _watermarkEngine = new WatermarkEngine();
  }
  return _watermarkEngine;
}
