// ─────────────────────────────────────────────────────────────
// Secure Document Control — Secure Viewer
//
// HTTP server providing a secure, anti-copy document viewing
// experience. Documents are rendered with real-time dynamic
// watermarks tied to the viewer's identity.
//
// Routes:
//   GET  /                        — Dashboard / status
//   GET  /health                  — Health check
//   GET  /view/:tokenSecret       — Secure document viewer
//   POST /view/:tokenSecret/log   — Log viewer action (scroll, etc)
//   GET  /api/ledger/:documentId  — Access ledger for document
//   GET  /api/stats               — SDC statistics
//
// Security:
//   - Token-validated access only
//   - No right-click, no copy/paste, no print (configurable)
//   - Dynamic watermark updates every 60 seconds
//   - Screenshot deterrence overlay on key combinations
//   - All access logged to append-only access ledger
//   - Device fingerprint binding
//   - OTP verification gate (if required)
// ─────────────────────────────────────────────────────────────

import http from "http";
import crypto from "crypto";
import { getAccessTokenService, AccessTokenService } from "./accessTokenService";
import { getWatermarkEngine, WatermarkEngine } from "./watermarkEngine";
import { getAccessLedger, AccessLedger } from "./accessLedger";
import { getDocumentIntakeEngine, DocumentIntakeEngine } from "./documentIntakeEngine";

// ── Types ────────────────────────────────────────────────────

export interface ViewerConfig {
  port: number;
  host: string;
}

// ── Route Parser ─────────────────────────────────────────────

interface RouteMatch {
  route: string;
  params: Record<string, string>;
}

function parseRoute(pathname: string): RouteMatch {
  const parts = pathname.split("/").filter(Boolean);

  if (parts.length === 0) return { route: "dashboard", params: {} };
  if (parts[0] === "health") return { route: "health", params: {} };

  if (parts[0] === "view" && parts.length >= 2) {
    if (parts.length === 3 && parts[2] === "log") {
      return { route: "view-log", params: { tokenSecret: parts[1] } };
    }
    return { route: "view", params: { tokenSecret: parts[1] } };
  }

  if (parts[0] === "api") {
    if (parts[1] === "ledger" && parts.length >= 3) {
      return { route: "api-ledger", params: { documentId: parts[2] } };
    }
    if (parts[1] === "stats") {
      return { route: "api-stats", params: {} };
    }
  }

  return { route: "not-found", params: {} };
}

// ── HTML Helpers ─────────────────────────────────────────────

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function jsonResponse(res: http.ServerResponse, data: unknown, status = 200): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data, null, 2));
}

function htmlResponse(res: http.ServerResponse, html: string, status = 200): void {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline';",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
  });
  res.end(html);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk: Buffer) => (body += chunk.toString()));
    req.on("end", () => resolve(body));
  });
}

// ── Secure Viewer Pages ──────────────────────────────────────

function renderDashboard(
  tokenService: AccessTokenService,
  ledger: AccessLedger,
  intakeEngine: DocumentIntakeEngine
): string {
  const tokenStats = tokenService.getStats();
  const ledgerStats = ledger.getStats();
  const intakeStats = intakeEngine.getStats();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SDC Secure Viewer — Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }
    .header { background: #161b22; border-bottom: 1px solid #30363d; padding: 20px 40px; }
    .header h1 { font-size: 20px; color: #58a6ff; }
    .header .subtitle { font-size: 12px; color: #8b949e; margin-top: 4px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; padding: 24px 40px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
    .card h3 { font-size: 14px; color: #58a6ff; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #21262d; }
    .stat:last-child { border-bottom: none; }
    .stat .label { color: #8b949e; font-size: 13px; }
    .stat .value { color: #f0f6fc; font-weight: 600; font-size: 13px; }
    .chain-status { padding: 8px 16px; border-radius: 4px; text-align: center; margin-top: 8px; font-size: 12px; }
    .chain-ok { background: #0d1117; border: 1px solid #238636; color: #3fb950; }
    .chain-broken { background: #0d1117; border: 1px solid #da3633; color: #f85149; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Secure Document Control — Viewer Dashboard</h1>
    <div class="subtitle">Document Intelligence Engine — SDC Layer</div>
  </div>
  <div class="grid">
    <div class="card">
      <h3>Document Intake</h3>
      <div class="stat"><span class="label">Total Intake Records</span><span class="value">${intakeStats.total}</span></div>
      <div class="stat"><span class="label">By Risk: LOW</span><span class="value">${intakeStats.byRiskTier["LOW"] || 0}</span></div>
      <div class="stat"><span class="label">By Risk: HIGH</span><span class="value">${intakeStats.byRiskTier["HIGH"] || 0}</span></div>
      <div class="stat"><span class="label">By Risk: CRITICAL</span><span class="value">${intakeStats.byRiskTier["CRITICAL"] || 0}</span></div>
    </div>
    <div class="card">
      <h3>Access Tokens</h3>
      <div class="stat"><span class="label">Total Issued</span><span class="value">${tokenStats.total}</span></div>
      <div class="stat"><span class="label">Active</span><span class="value">${tokenStats.active}</span></div>
      <div class="stat"><span class="label">Expired</span><span class="value">${tokenStats.expired}</span></div>
      <div class="stat"><span class="label">Revoked</span><span class="value">${tokenStats.revoked}</span></div>
    </div>
    <div class="card">
      <h3>Access Ledger</h3>
      <div class="stat"><span class="label">Total Events</span><span class="value">${ledgerStats.totalEntries}</span></div>
      <div class="stat"><span class="label">Unique Documents</span><span class="value">${ledgerStats.uniqueDocuments}</span></div>
      <div class="stat"><span class="label">Unique Actors</span><span class="value">${ledgerStats.uniqueActors}</span></div>
      <div class="stat"><span class="label">Denials</span><span class="value">${ledgerStats.denialCount}</span></div>
      <div class="chain-status ${ledgerStats.chainIntact ? "chain-ok" : "chain-broken"}">
        Chain Integrity: ${ledgerStats.chainIntact ? "VERIFIED" : "BROKEN"}
      </div>
    </div>
  </div>
</body>
</html>`;
}

function renderAccessDenied(reason: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117; color: #c9d1d9;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh;
    }
    .denied {
      text-align: center;
      max-width: 480px;
      padding: 40px;
    }
    .denied h1 {
      font-size: 48px;
      color: #da3633;
      margin-bottom: 16px;
    }
    .denied p {
      color: #8b949e;
      margin-bottom: 8px;
    }
    .denied .reason {
      background: #161b22;
      border: 1px solid #30363d;
      padding: 16px;
      border-radius: 8px;
      margin-top: 16px;
      font-size: 13px;
      color: #f85149;
    }
  </style>
</head>
<body>
  <div class="denied">
    <h1>ACCESS DENIED</h1>
    <p>Your access to this document has been denied.</p>
    <p>This attempt has been logged.</p>
    <div class="reason">${escapeHtml(reason)}</div>
  </div>
</body>
</html>`;
}

function renderSecureDocument(params: {
  documentTitle: string;
  documentContent: string;
  recipientName: string;
  recipientEmail: string;
  tokenSecret: string;
  confidentialityNotice: string;
  watermarkOverlay: string;
  watermarkCSS: string;
  watermarkScript: string;
  footerHash: string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(params.documentTitle)} — Secure View</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Georgia', 'Times New Roman', serif;
      background: #1a1a1a;
      color: #e0e0e0;
      -webkit-user-select: none;
      -moz-user-select: none;
      -ms-user-select: none;
      user-select: none;
    }

    /* ── Top Bar ── */
    .secure-bar {
      position: fixed;
      top: 0; left: 0; right: 0;
      background: #0d1117;
      border-bottom: 2px solid #da3633;
      padding: 8px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      z-index: 9999;
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 11px;
    }
    .secure-bar .badge {
      background: #da3633;
      color: white;
      padding: 2px 8px;
      border-radius: 3px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .secure-bar .viewer-info { color: #8b949e; }

    /* ── Document Container ── */
    .doc-container {
      max-width: 800px;
      margin: 80px auto 60px;
      background: #ffffff;
      color: #1a1a1a;
      padding: 60px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.5);
      position: relative;
      line-height: 1.7;
    }

    .doc-header {
      border-bottom: 2px solid #1a1a1a;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .doc-header h1 { font-size: 22px; margin-bottom: 4px; }

    .doc-notice {
      background: #fff3cd;
      border: 1px solid #ffc107;
      color: #856404;
      padding: 12px 16px;
      font-size: 11px;
      margin-bottom: 24px;
    }

    .doc-content {
      font-size: 14px;
      line-height: 1.7;
    }

    .doc-footer {
      margin-top: 40px;
      border-top: 1px solid #ccc;
      padding-top: 8px;
      font-size: 9px;
      color: #999;
      font-family: 'Segoe UI', system-ui, sans-serif;
    }

    /* ── Anti-Copy Shield ── */
    .copy-shield {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      z-index: 100;
      pointer-events: none;
    }

    /* ── Screenshot Deterrence Overlay ── */
    .screenshot-overlay {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(218, 54, 51, 0.85);
      z-index: 99999;
      justify-content: center;
      align-items: center;
      font-size: 32px;
      color: white;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 4px;
    }

    /* ── Print Styles ── */
    @media print {
      body { background: white; }
      .secure-bar { display: none; }
      .doc-container {
        box-shadow: none;
        margin: 0;
        padding: 0.5in;
      }
      .doc-content::before {
        content: "CONFIDENTIAL — Printed copy tracked";
        display: block;
        text-align: center;
        font-size: 14px;
        color: red;
        margin-bottom: 12px;
      }
    }

    ${params.watermarkCSS}
  </style>
</head>
<body>
  <!-- Security Top Bar -->
  <div class="secure-bar">
    <span class="badge">SECURE VIEW</span>
    <span class="viewer-info">
      Viewing as: ${escapeHtml(params.recipientName)} &lt;${escapeHtml(params.recipientEmail)}&gt;
    </span>
    <span class="viewer-info" id="sdc-timer"></span>
  </div>

  <!-- Document -->
  <div class="doc-container">
    <div class="copy-shield"></div>

    <div class="doc-header">
      <h1>${escapeHtml(params.documentTitle)}</h1>
    </div>

    <div class="doc-notice">
      ${escapeHtml(params.confidentialityNotice)}
    </div>

    <div class="doc-content sdc-protected">
      ${params.documentContent}
    </div>

    <div class="doc-footer">
      <div>Viewed by: ${escapeHtml(params.recipientName)} &lt;${escapeHtml(params.recipientEmail)}&gt;</div>
      <div>Hash: ${params.footerHash}</div>
      <div id="sdc-timestamp"></div>
    </div>

    ${params.watermarkOverlay}
  </div>

  <!-- Screenshot Deterrence -->
  <div class="screenshot-overlay" id="sdc-screenshot-overlay">
    SCREENSHOT DETECTED — THIS EVENT HAS BEEN LOGGED
  </div>

  <!-- Security Scripts -->
  <script>
    // Timer
    const timerEl = document.getElementById('sdc-timer');
    const tsEl = document.getElementById('sdc-timestamp');
    let startTime = Date.now();
    setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      const m = Math.floor(elapsed / 60);
      const s = elapsed % 60;
      if (timerEl) timerEl.textContent = 'Session: ' + m + 'm ' + s + 's';
      if (tsEl) tsEl.textContent = 'Timestamp: ' + new Date().toISOString();
    }, 1000);

    // Context menu block
    document.addEventListener('contextmenu', function(e) {
      e.preventDefault();
      logAction('context-menu-blocked');
    });

    // Copy block
    document.addEventListener('copy', function(e) {
      e.preventDefault();
      if (e.clipboardData) {
        e.clipboardData.setData('text/plain',
          'COPY BLOCKED — This document is protected by Secure Document Control. ' +
          'This attempt has been logged.'
        );
      }
      logAction('copy-blocked');
    });

    // Cut block
    document.addEventListener('cut', function(e) {
      e.preventDefault();
      logAction('cut-blocked');
    });

    // Drag block
    document.addEventListener('dragstart', function(e) {
      e.preventDefault();
      logAction('drag-blocked');
    });

    // Print detection
    window.addEventListener('beforeprint', function() {
      logAction('print-detected');
    });

    // Screenshot deterrence (PrintScreen, Ctrl+P, Cmd+Shift+3/4)
    document.addEventListener('keydown', function(e) {
      // PrintScreen
      if (e.key === 'PrintScreen' || e.keyCode === 44) {
        e.preventDefault();
        showScreenshotOverlay();
        logAction('screenshot-key-detected');
      }
      // Ctrl+P (print)
      if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
        e.preventDefault();
        logAction('print-shortcut-blocked');
      }
      // Ctrl+S (save)
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        logAction('save-shortcut-blocked');
      }
      // Ctrl+A (select all)
      if ((e.ctrlKey || e.metaKey) && e.key === 'a') {
        e.preventDefault();
        logAction('select-all-blocked');
      }
      // F12 / DevTools
      if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i'))) {
        e.preventDefault();
        logAction('devtools-blocked');
      }
    });

    // Visibility change (tab switch, minimize)
    document.addEventListener('visibilitychange', function() {
      if (document.hidden) {
        logAction('tab-hidden');
      } else {
        logAction('tab-visible');
      }
    });

    // Screenshot overlay
    function showScreenshotOverlay() {
      const overlay = document.getElementById('sdc-screenshot-overlay');
      if (overlay) {
        overlay.style.display = 'flex';
        setTimeout(() => { overlay.style.display = 'none'; }, 3000);
      }
    }

    // Log viewer actions to server
    function logAction(action) {
      try {
        navigator.sendBeacon('/view/${params.tokenSecret}/log',
          JSON.stringify({ action: action, timestamp: new Date().toISOString() })
        );
      } catch(e) { /* silent */ }
    }

    // Log initial view
    logAction('document-viewed');

    // Periodic heartbeat
    setInterval(function() {
      logAction('heartbeat');
    }, 30000);

    ${params.watermarkScript}
  </script>
</body>
</html>`;
}

// ── Secure Viewer Server ─────────────────────────────────────

export function startSecureViewer(config: Partial<ViewerConfig> = {}): http.Server {
  const port = config.port || 3003;
  const host = config.host || "127.0.0.1";

  const tokenService = getAccessTokenService();
  const watermarkEngine = getWatermarkEngine();
  const ledger = getAccessLedger();
  const intakeEngine = getDocumentIntakeEngine();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://${host}:${port}`);
    const method = req.method?.toUpperCase() || "GET";

    // CORS
    if (method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    const { route, params } = parseRoute(url.pathname);
    const clientIP = req.socket.remoteAddress || "unknown";
    const userAgent = req.headers["user-agent"] || "unknown";

    try {
      switch (route) {
        // ── Dashboard ──
        case "dashboard": {
          const html = renderDashboard(tokenService, ledger, intakeEngine);
          htmlResponse(res, html);
          break;
        }

        // ── Health ──
        case "health": {
          const integrity = ledger.verifyIntegrity();
          jsonResponse(res, {
            status: "ok",
            service: "SDC Secure Viewer",
            port,
            ledgerIntegrity: integrity.verified,
            timestamp: new Date().toISOString(),
          });
          break;
        }

        // ── Secure View ──
        case "view": {
          const { tokenSecret } = params;
          const deviceFP = crypto.createHash("sha256").update(clientIP + userAgent).digest("hex").substring(0, 16);
          const validation = tokenService.validate(tokenSecret, clientIP, deviceFP, userAgent);

          if (!validation.valid) {
            // Log denial
            ledger.record({
              documentId: validation.token?.documentId || "unknown",
              tokenId: validation.token?.tokenId,
              action: "access-denied",
              actor: validation.token?.recipient?.email || "unknown",
              ipAddress: clientIP,
              userAgent,
              details: `Secure view denied: ${validation.reason}`,
              result: "denied",
              denialReason: validation.reason,
            });

            htmlResponse(res, renderAccessDenied(validation.reason || "Access denied"), 403);
            return;
          }

          const token = validation.token!;

          // Check if OTP required and not yet verified
          if (validation.requiresOTP) {
            // For now, render OTP requirement page
            htmlResponse(res, renderOTPRequired(token.tokenId, tokenSecret));

            ledger.record({
              documentId: token.documentId,
              tokenId: token.tokenId,
              action: "auth-failed",
              actor: token.recipient.email,
              ipAddress: clientIP,
              userAgent,
              details: "OTP verification required before viewing",
              result: "denied",
              denialReason: "OTP not verified",
            });
            return;
          }

          // Get intake record for document metadata
          const intake = intakeEngine.getByDocumentId(token.documentId);

          const documentTitle = intake?.documentTitle || "Secure Document";
          const confidentialityNotice = intake?.confidentialityNotice || "CONFIDENTIAL — All access is monitored and logged.";
          const watermarkPolicy = intake?.watermarkPolicy || "STANDARD";

          // Generate watermark for this viewer
          const watermark = watermarkEngine.generate({
            documentId: token.documentId,
            documentTitle,
            recipient: {
              name: token.recipient.name,
              email: token.recipient.email,
              ip: clientIP,
              accessToken: token.tokenId,
            },
            policy: watermarkPolicy,
            confidentialityNotice,
          });

          // Build secure viewer page
          // In a real system, documentContent would be fetched from storage
          const documentContent = `<p><em>Document content rendered securely via SDC Secure Viewer.</em></p>
<p>Document ID: ${token.documentId.substring(0, 16)}...</p>
<p>This content is protected by the Secure Document Control layer.</p>`;

          const html = renderSecureDocument({
            documentTitle,
            documentContent,
            recipientName: token.recipient.name,
            recipientEmail: token.recipient.email,
            tokenSecret,
            confidentialityNotice,
            watermarkOverlay: watermark.htmlOverlay,
            watermarkCSS: watermark.cssStyles,
            watermarkScript: watermark.dynamicScript,
            footerHash: watermark.payload.footerHash,
          });

          // Log access
          ledger.record({
            documentId: token.documentId,
            intakeId: intake?.intakeId,
            tokenId: token.tokenId,
            action: "viewed",
            actor: token.recipient.email,
            organization: token.recipient.organization,
            ipAddress: clientIP,
            userAgent,
            details: `Secure view opened for "${documentTitle}"`,
            result: "granted",
            watermarkId: watermark.payload.watermarkId,
          });

          htmlResponse(res, html);
          break;
        }

        // ── View Action Log (beacon endpoint) ──
        case "view-log": {
          if (method !== "POST") {
            res.writeHead(405).end();
            return;
          }

          const body = await readBody(req);
          let action = "unknown";
          try {
            const parsed = JSON.parse(body);
            action = parsed.action || "unknown";
          } catch {
            action = "malformed-log";
          }

          const { tokenSecret } = params;
          const token = tokenService.getBySecret(tokenSecret);

          if (token) {
            // Map viewer actions to ledger actions
            const ledgerAction = mapViewerAction(action);

            ledger.record({
              documentId: token.documentId,
              tokenId: token.tokenId,
              action: ledgerAction,
              actor: token.recipient.email,
              ipAddress: clientIP,
              userAgent,
              details: `Viewer event: ${action}`,
              result: ledgerAction === "screenshot-detected" || ledgerAction === "copied"
                ? "denied"
                : "info",
            });
          }

          res.writeHead(204).end();
          break;
        }

        // ── API: Ledger ──
        case "api-ledger": {
          const entries = ledger.getByDocument(params.documentId);
          jsonResponse(res, {
            documentId: params.documentId,
            entries: entries.length,
            timeline: ledger.getTimeline(params.documentId),
            data: entries.slice(-50),
          });
          break;
        }

        // ── API: Stats ──
        case "api-stats": {
          const tokenStats = tokenService.getStats();
          const ledgerStats = ledger.getStats();
          const intakeStats = intakeEngine.getStats();
          const integrity = ledger.verifyIntegrity();

          jsonResponse(res, {
            intake: intakeStats,
            tokens: tokenStats,
            ledger: ledgerStats,
            chainIntegrity: integrity,
          });
          break;
        }

        // ── 404 ──
        default: {
          res.writeHead(404, { "Content-Type": "text/plain" });
          res.end("Not Found");
        }
      }
    } catch (err) {
      console.error("[SDC-VIEWER] Error:", err);
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Internal Server Error");
    }
  });

  server.listen(port, host, () => {
    console.log(`[SDC-VIEWER] Secure viewer listening on http://${host}:${port}`);
    console.log(`[SDC-VIEWER]   Dashboard:  http://${host}:${port}/`);
    console.log(`[SDC-VIEWER]   View:       http://${host}:${port}/view/<tokenSecret>`);
    console.log(`[SDC-VIEWER]   Stats API:  http://${host}:${port}/api/stats`);
  });

  return server;
}

// ── OTP Page ─────────────────────────────────────────────────

function renderOTPRequired(tokenId: string, tokenSecret: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OTP Verification Required</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117; color: #c9d1d9;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh;
    }
    .otp-box {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 40px;
      max-width: 400px;
      text-align: center;
    }
    .otp-box h2 { color: #58a6ff; margin-bottom: 16px; }
    .otp-box p { color: #8b949e; font-size: 13px; margin-bottom: 24px; }
    .otp-box .token-ref {
      font-family: monospace;
      font-size: 11px;
      color: #484f58;
      margin-top: 16px;
    }
  </style>
</head>
<body>
  <div class="otp-box">
    <h2>Verification Required</h2>
    <p>
      This document requires OTP verification before viewing.
      Please verify your identity through the signing gateway first.
    </p>
    <p>
      Contact the document owner to request OTP verification
      for your access token.
    </p>
    <div class="token-ref">Token: ${tokenId.substring(0, 12)}...</div>
  </div>
</body>
</html>`;
}

// ── Helpers ──────────────────────────────────────────────────

function mapViewerAction(action: string): import("./accessLedger").AccessAction {
  const mapping: Record<string, import("./accessLedger").AccessAction> = {
    "document-viewed": "viewed",
    "heartbeat": "viewed",
    "context-menu-blocked": "copied",
    "copy-blocked": "copied",
    "cut-blocked": "copied",
    "drag-blocked": "copied",
    "print-detected": "printed",
    "print-shortcut-blocked": "printed",
    "screenshot-key-detected": "screenshot-detected",
    "save-shortcut-blocked": "downloaded",
    "select-all-blocked": "copied",
    "devtools-blocked": "screenshot-detected",
    "tab-hidden": "viewed",
    "tab-visible": "viewed",
  };
  return mapping[action] || "viewed";
}
