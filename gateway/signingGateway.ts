// ─────────────────────────────────────────────────────────────
// Signing Gateway — Sovereign Signing HTTP Server
//
// A self-contained HTTP server that presents a 1-click signing
// experience. Each signer receives a unique, secure URL:
//
//   http://localhost:3002/sign/<access_token>
//
// Flow:
//   1. Signer taps link → document preview + initials + sign
//   2. Intent is logged (IP, user agent, consent, timestamp)
//   3. OTP verification if configured
//   4. Signature recorded → session updated
//   5. On threshold met → auto-finalize
//
// Routes:
//   GET  /                     — Gateway dashboard
//   GET  /health               — Health check
//   GET  /sign/:token          — Signing page (HTML)
//   POST /sign/:token          — Submit signature
//   POST /sign/:token/initial  — Submit initial for section
//   POST /sign/:token/otp      — Request OTP
//   POST /sign/:token/verify-otp — Verify OTP
//   GET  /session/:id          — Session status (JSON)
//   GET  /session/:id/evidence — Intent evidence report
//   POST /session              — Create session (API)
// ─────────────────────────────────────────────────────────────

import http from "http";
import crypto from "crypto";
import {
  SigningSessionEngine,
  getSigningSessionEngine,
  SigningSession,
  SessionSigner,
} from "./signingSession";
import { IntentLogger, getIntentLogger, DeviceEvidence, IntentAction } from "./intentLogger";
import { OTPEngine, getOTPEngine } from "./otpEngine";
import { DistributionEngine } from "./distributionEngine";
import { getSignatureEngine } from "../signature/signatureEngine";

// ── Types ────────────────────────────────────────────────────

export interface GatewayConfig {
  port: number;
  host: string;
}

interface GatewayResponse {
  success: boolean;
  data?: any;
  error?: string;
  timestamp: string;
}

// ── HTTP Helpers ─────────────────────────────────────────────

function sendJSON(res: http.ServerResponse, status: number, body: GatewayResponse): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(JSON.stringify(body, null, 2));
}

function sendHTML(res: http.ServerResponse, html: string): void {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function getClientIP(req: http.IncomingMessage): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const ip = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0];
    return ip.trim();
  }
  return req.socket.remoteAddress || "unknown";
}

function getDeviceEvidence(req: http.IncomingMessage): DeviceEvidence {
  const ua = req.headers["user-agent"] || "unknown";
  const fingerprint = crypto
    .createHash("sha256")
    .update(`${ua}:${req.headers["accept-language"] || ""}:${req.headers["accept-encoding"] || ""}`)
    .digest("hex");

  return {
    userAgent: ua,
    clientName: parseClientName(ua),
    osName: parseOSName(ua),
    deviceFingerprint: fingerprint,
    platform: parsePlatform(ua),
    language: req.headers["accept-language"]?.split(",")[0] || undefined,
  };
}

function parseClientName(ua: string): string {
  if (ua.includes("Chrome")) return "Chrome";
  if (ua.includes("Firefox")) return "Firefox";
  if (ua.includes("Safari")) return "Safari";
  if (ua.includes("Edge")) return "Edge";
  return "Unknown";
}

function parseOSName(ua: string): string {
  if (ua.includes("Windows")) return "Windows";
  if (ua.includes("Mac OS")) return "macOS";
  if (ua.includes("Linux")) return "Linux";
  if (ua.includes("Android")) return "Android";
  if (ua.includes("iOS") || ua.includes("iPhone")) return "iOS";
  return "Unknown";
}

function parsePlatform(ua: string): string {
  if (ua.includes("Mobile")) return "mobile";
  if (ua.includes("Tablet")) return "tablet";
  return "desktop";
}

function parseRoute(pathname: string): { route: string; params: string[] } {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 0) return { route: "/", params: [] };
  return { route: `/${parts[0]}`, params: parts.slice(1) };
}

// ── Signing Page HTML ────────────────────────────────────────

function renderSigningPage(session: SigningSession, signer: SessionSigner): string {
  const initialsHtml = signer.requiredInitials.length > 0
    ? signer.requiredInitials.map((sectionId) => {
        const completed = signer.completedInitials.includes(sectionId);
        return `
          <div class="initial-row ${completed ? "completed" : ""}">
            <div class="initial-label">
              <span class="section-name">${sectionId}</span>
              ${completed ? '<span class="check">&#10003;</span>' : ""}
            </div>
            ${
              completed
                ? '<div class="initial-status">Initialed</div>'
                : `<button class="btn btn-initial" onclick="submitInitial('${sectionId}')">Initial</button>`
            }
          </div>`;
      }).join("")
    : '<p class="no-initials">No section initials required.</p>';

  const allInitialed =
    signer.requiredInitials.length === 0 ||
    signer.requiredInitials.every((s) => signer.completedInitials.includes(s));

  const signButtonDisabled = !allInitialed ? "disabled" : "";
  const signButtonClass = allInitialed ? "btn btn-sign" : "btn btn-sign btn-disabled";

  const requireOTP = session.config.requireOTP;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign: ${session.documentTitle}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #1a1a2e; }
    .container { max-width: 640px; margin: 0 auto; padding: 24px 16px; }
    .header { text-align: center; padding: 32px 0 24px; }
    .header h1 { font-size: 24px; color: #1a1a2e; margin-bottom: 8px; }
    .header p { color: #666; font-size: 14px; }
    .card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
    .card h2 { font-size: 18px; margin-bottom: 16px; color: #1a1a2e; }
    .meta-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
    .meta-row .label { color: #888; }
    .meta-row .value { font-weight: 600; }
    .initial-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #f5f5f5; }
    .initial-row.completed { opacity: 0.6; }
    .initial-label { display: flex; align-items: center; gap: 8px; }
    .section-name { font-size: 14px; font-weight: 500; }
    .check { color: #22c55e; font-size: 18px; font-weight: bold; }
    .initial-status { color: #22c55e; font-size: 13px; font-weight: 500; }
    .no-initials { color: #888; font-size: 14px; font-style: italic; }
    .consent-box { display: flex; align-items: flex-start; gap: 12px; padding: 16px; background: #fafafa; border-radius: 8px; margin-bottom: 16px; }
    .consent-box input[type="checkbox"] { margin-top: 3px; transform: scale(1.2); }
    .consent-box label { font-size: 13px; color: #555; line-height: 1.5; }
    .btn { padding: 14px 28px; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s; width: 100%; }
    .btn-initial { background: #e8f0fe; color: #3366cc; padding: 8px 16px; width: auto; font-size: 13px; border-radius: 6px; }
    .btn-initial:hover { background: #d0e0fc; }
    .btn-sign { background: #3366cc; color: white; margin-top: 8px; }
    .btn-sign:hover:not(:disabled) { background: #2855b0; }
    .btn-sign:disabled, .btn-disabled { background: #ccc; color: #888; cursor: not-allowed; }
    .btn-otp { background: #f59e0b; color: white; margin-bottom: 12px; }
    .btn-otp:hover { background: #d97706; }
    .otp-section { display: ${requireOTP ? "block" : "none"}; }
    .otp-input { width: 100%; padding: 14px; font-size: 24px; text-align: center; letter-spacing: 12px; border: 2px solid #ddd; border-radius: 8px; margin: 12px 0; font-family: monospace; }
    .status { padding: 12px 16px; border-radius: 8px; margin-top: 12px; font-size: 14px; display: none; }
    .status.success { display: block; background: #dcfce7; color: #166534; }
    .status.error { display: block; background: #fef2f2; color: #991b1b; }
    .status.info { display: block; background: #e8f0fe; color: #1e40af; }
    .footer { text-align: center; padding: 24px; color: #999; font-size: 12px; }
    .signed-banner { background: #dcfce7; border: 2px solid #22c55e; text-align: center; padding: 24px; border-radius: 12px; }
    .signed-banner h2 { color: #166534; }
    .signed-banner p { color: #166534; margin-top: 8px; }
    @media (max-width: 480px) {
      .container { padding: 12px; }
      .card { padding: 16px; }
      .header h1 { font-size: 20px; }
    }
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Signature Request</h1>
    <p>Sovereign Document Engine</p>
  </div>

  ${
    signer.status === "signed"
      ? `<div class="signed-banner">
           <h2>&#10003; Signed Successfully</h2>
           <p>Signed at ${signer.signedAt}</p>
           <p>Signature hash: ${signer.signatureHash?.substring(0, 24)}...</p>
         </div>`
      : signer.status === "rejected"
      ? `<div class="card" style="border: 2px solid #ef4444;">
           <h2 style="color: #991b1b;">Signature Rejected</h2>
           <p>${signer.rejectionReason || "No reason given"}</p>
         </div>`
      : `
  <!-- Document Info -->
  <div class="card">
    <h2>${session.documentTitle}</h2>
    <div class="meta-row"><span class="label">Requested by</span><span class="value">${session.creator.name}</span></div>
    <div class="meta-row"><span class="label">Your role</span><span class="value">${signer.role}</span></div>
    <div class="meta-row"><span class="label">Document hash</span><span class="value">${session.documentHash.substring(0, 16)}...</span></div>
    <div class="meta-row"><span class="label">Deadline</span><span class="value">${new Date(session.config.expiresAt).toLocaleDateString()}</span></div>
  </div>

  <!-- Initials -->
  <div class="card">
    <h2>Section Initials</h2>
    ${initialsHtml}
  </div>

  <!-- OTP Verification -->
  <div class="otp-section card">
    <h2>Identity Verification</h2>
    <p style="color: #666; font-size: 14px; margin-bottom: 12px;">A one-time code will be sent to verify your identity before signing.</p>
    <button class="btn btn-otp" onclick="requestOTP()" id="otpBtn">Send Verification Code</button>
    <input type="text" class="otp-input" id="otpInput" placeholder="000000" maxlength="6" style="display: none;">
    <button class="btn btn-initial" onclick="verifyOTP()" id="verifyOtpBtn" style="display: none; width: 100%; margin-top: 8px;">Verify Code</button>
    <div id="otpStatus" class="status"></div>
  </div>

  <!-- Sign -->
  <div class="card">
    <h2>Sign Document</h2>
    <div class="consent-box">
      <input type="checkbox" id="consent" onchange="updateSignButton()">
      <label for="consent">
        I, <strong>${signer.name}</strong>, acknowledge that I have reviewed this document
        and agree to sign it electronically. I understand this constitutes a legally binding
        signature under ESIGN and UETA frameworks.
      </label>
    </div>
    <button class="btn ${signButtonClass}" id="signBtn" ${signButtonDisabled} onclick="submitSignature()">
      Sign Document
    </button>
    <div id="signStatus" class="status"></div>
  </div>
  `
  }

  <div class="footer">
    <p>Sovereign Document Engine &mdash; Institution-Grade Signing Gateway</p>
    <p>Session: ${session.sessionId.substring(0, 12)}... | Signer: ${signer.signerId.substring(0, 12)}...</p>
  </div>
</div>

<script>
const TOKEN = '${signer.accessToken}';
let otpVerified = ${!requireOTP};
let allInitialed = ${allInitialed};

function updateSignButton() {
  const consent = document.getElementById('consent').checked;
  const btn = document.getElementById('signBtn');
  const canSign = consent && allInitialed && otpVerified;
  btn.disabled = !canSign;
  btn.className = canSign ? 'btn btn-sign' : 'btn btn-sign btn-disabled';
}

async function submitInitial(sectionId) {
  try {
    const resp = await fetch('/sign/' + TOKEN + '/initial', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sectionId })
    });
    const data = await resp.json();
    if (data.success) {
      location.reload();
    } else {
      showStatus('signStatus', data.error, 'error');
    }
  } catch (e) {
    showStatus('signStatus', 'Network error', 'error');
  }
}

async function requestOTP() {
  try {
    document.getElementById('otpBtn').disabled = true;
    const resp = await fetch('/sign/' + TOKEN + '/otp', { method: 'POST' });
    const data = await resp.json();
    if (data.success) {
      document.getElementById('otpInput').style.display = 'block';
      document.getElementById('verifyOtpBtn').style.display = 'block';
      showStatus('otpStatus', 'Verification code sent. Check your email/phone.', 'info');
    } else {
      showStatus('otpStatus', data.error, 'error');
      document.getElementById('otpBtn').disabled = false;
    }
  } catch (e) {
    showStatus('otpStatus', 'Network error', 'error');
    document.getElementById('otpBtn').disabled = false;
  }
}

async function verifyOTP() {
  const code = document.getElementById('otpInput').value.trim();
  if (code.length !== 6) {
    showStatus('otpStatus', 'Enter a 6-digit code', 'error');
    return;
  }
  try {
    const resp = await fetch('/sign/' + TOKEN + '/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    const data = await resp.json();
    if (data.success) {
      otpVerified = true;
      showStatus('otpStatus', 'Identity verified!', 'success');
      document.getElementById('otpInput').style.display = 'none';
      document.getElementById('verifyOtpBtn').style.display = 'none';
      document.getElementById('otpBtn').style.display = 'none';
      updateSignButton();
    } else {
      showStatus('otpStatus', data.error || data.data?.message || 'Invalid code', 'error');
    }
  } catch (e) {
    showStatus('otpStatus', 'Network error', 'error');
  }
}

async function submitSignature() {
  const btn = document.getElementById('signBtn');
  btn.disabled = true;
  btn.textContent = 'Signing...';
  
  try {
    const resp = await fetch('/sign/' + TOKEN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        consent: true,
        consentText: document.querySelector('.consent-box label').innerText
      })
    });
    const data = await resp.json();
    if (data.success) {
      showStatus('signStatus', 'Document signed successfully!', 'success');
      setTimeout(() => location.reload(), 1500);
    } else {
      showStatus('signStatus', data.error || 'Signature failed', 'error');
      btn.disabled = false;
      btn.textContent = 'Sign Document';
    }
  } catch (e) {
    showStatus('signStatus', 'Network error', 'error');
    btn.disabled = false;
    btn.textContent = 'Sign Document';
  }
}

function showStatus(id, message, type) {
  const el = document.getElementById(id);
  el.textContent = message;
  el.className = 'status ' + type;
}
</script>
</body>
</html>`;
}

// ── Dashboard HTML ───────────────────────────────────────────

function renderDashboard(sessionEngine: SigningSessionEngine): string {
  const stats = sessionEngine.getStats();
  const sessions = sessionEngine.getAllSessions();

  const sessionRows = sessions.slice(-20).reverse().map((s) => {
    const statusColor = s.status === "completed" ? "#22c55e"
      : s.status === "expired" || s.status === "cancelled" ? "#ef4444"
      : "#f59e0b";
    return `
      <tr>
        <td><a href="/session/${s.sessionId}" style="color:#3366cc;">${s.sessionId.substring(0, 12)}...</a></td>
        <td>${s.documentTitle}</td>
        <td><span style="color:${statusColor};font-weight:600;">${s.status.toUpperCase()}</span></td>
        <td>${s.signatureCount}/${s.config.threshold}</td>
        <td>${s.signers.length}</td>
        <td>${new Date(s.createdAt).toLocaleDateString()}</td>
      </tr>`;
  }).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Signing Gateway — Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; padding: 24px; }
    .container { max-width: 960px; margin: 0 auto; }
    h1 { margin-bottom: 8px; color: #1a1a2e; }
    .subtitle { color: #666; margin-bottom: 24px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .stat { background: white; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }
    .stat .number { font-size: 28px; font-weight: 700; color: #3366cc; }
    .stat .label { font-size: 12px; color: #888; margin-top: 4px; }
    table { width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }
    th { background: #1a1a2e; color: white; padding: 12px 16px; text-align: left; font-size: 13px; }
    td { padding: 12px 16px; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
    tr:hover td { background: #fafafa; }
    a { text-decoration: none; }
  </style>
</head>
<body>
<div class="container">
  <h1>Signing Gateway</h1>
  <p class="subtitle">Sovereign Document Engine &mdash; Distribution & Signing Infrastructure</p>
  
  <div class="stats">
    <div class="stat"><div class="number">${stats.total}</div><div class="label">Total Sessions</div></div>
    <div class="stat"><div class="number">${stats.active}</div><div class="label">Active</div></div>
    <div class="stat"><div class="number">${stats.completed}</div><div class="label">Completed</div></div>
    <div class="stat"><div class="number">${stats.totalSignatures}</div><div class="label">Signatures</div></div>
    <div class="stat"><div class="number">${stats.expired}</div><div class="label">Expired</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Session ID</th>
        <th>Document</th>
        <th>Status</th>
        <th>Signatures</th>
        <th>Signers</th>
        <th>Created</th>
      </tr>
    </thead>
    <tbody>
      ${sessionRows || '<tr><td colspan="6" style="text-align:center;color:#888;padding:24px;">No sessions yet. Create one via CLI or API.</td></tr>'}
    </tbody>
  </table>
</div>
</body>
</html>`;
}

// ── Gateway Server ───────────────────────────────────────────

export function startSigningGateway(config: Partial<GatewayConfig> = {}): http.Server {
  const port = config.port || 3002;
  const host = config.host || "127.0.0.1";

  const sessionEngine = getSigningSessionEngine();
  const intentLogger = getIntentLogger();
  const otpEngine = getOTPEngine();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://${host}:${port}`);
    const method = req.method?.toUpperCase() || "GET";

    // CORS preflight
    if (method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      });
      res.end();
      return;
    }

    const { route, params } = parseRoute(url.pathname);

    try {
      // ── GET / — Dashboard ──────────────────────────────────
      if (method === "GET" && route === "/") {
        return sendHTML(res, renderDashboard(sessionEngine));
      }

      // ── GET /health ────────────────────────────────────────
      if (method === "GET" && route === "/health") {
        return sendJSON(res, 200, {
          success: true,
          data: {
            status: "operational",
            sessions: sessionEngine.getStats(),
            intents: intentLogger.getTotalRecords(),
          },
          timestamp: new Date().toISOString(),
        });
      }

      // ── GET /sign/:token — Signing page ────────────────────
      if (method === "GET" && route === "/sign" && params.length >= 1) {
        const token = params[0];

        // Sub-routes (initial, otp, verify-otp handled as POST below)
        if (params.length > 1) {
          return sendJSON(res, 404, { success: false, error: "Not found", timestamp: new Date().toISOString() });
        }

        const resolved = sessionEngine.resolveToken(token);
        if (!resolved) {
          return sendHTML(res, renderErrorPage("Invalid or expired signing link", "This link may have expired or already been used."));
        }

        const { session, signer } = resolved;

        // Log view intent
        sessionEngine.recordView(session.sessionId, signer.signerId);
        intentLogger.log({
          sessionId: session.sessionId,
          documentId: session.documentId,
          signerId: signer.signerId,
          signerEmail: signer.email,
          signerName: signer.name,
          action: "document-viewed",
          ipAddress: getClientIP(req),
          device: getDeviceEvidence(req),
        });

        return sendHTML(res, renderSigningPage(session, signer));
      }

      // ── POST /sign/:token — Submit signature ───────────────
      if (method === "POST" && route === "/sign" && params.length >= 1) {
        const token = params[0];

        // Sub-routes
        if (params.length >= 2) {
          const subRoute = params[1];

          // POST /sign/:token/initial
          if (subRoute === "initial") {
            return await handleInitial(token, req, res, sessionEngine, intentLogger);
          }

          // POST /sign/:token/otp
          if (subRoute === "otp") {
            return await handleOTPRequest(token, req, res, sessionEngine, otpEngine, intentLogger);
          }

          // POST /sign/:token/verify-otp
          if (subRoute === "verify-otp") {
            return await handleOTPVerify(token, req, res, sessionEngine, otpEngine, intentLogger);
          }

          return sendJSON(res, 404, { success: false, error: "Not found", timestamp: new Date().toISOString() });
        }

        // Main signature submission
        return await handleSignature(token, req, res, sessionEngine, intentLogger);
      }

      // ── GET /session/:id — Session status ──────────────────
      if (method === "GET" && route === "/session" && params.length >= 1) {
        const sessionId = params[0];

        // Sub-route: evidence report
        if (params.length >= 2 && params[1] === "evidence") {
          const report = intentLogger.generateEvidenceReport(sessionId);
          res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
          res.end(report);
          return;
        }

        const session = sessionEngine.getSession(sessionId);
        if (!session) {
          return sendJSON(res, 404, { success: false, error: "Session not found", timestamp: new Date().toISOString() });
        }

        return sendJSON(res, 200, {
          success: true,
          data: {
            sessionId: session.sessionId,
            documentTitle: session.documentTitle,
            status: session.status,
            signatureCount: session.signatureCount,
            threshold: session.config.threshold,
            thresholdMet: session.thresholdMet,
            expiresAt: session.config.expiresAt,
            signers: session.signers.map((s) => ({
              name: s.name,
              email: s.email,
              role: s.role,
              status: s.status,
              signedAt: s.signedAt,
              viewCount: s.viewCount,
            })),
            artifacts: session.artifacts,
          },
          timestamp: new Date().toISOString(),
        });
      }

      // ── POST /session — Create session (API) ───────────────
      if (method === "POST" && route === "/session") {
        const body = JSON.parse(await readBody(req));
        const { documentId, documentTitle, documentHash, sku, creator, signers, threshold, requireAll, ordering, expiresInHours, requireOTP, requiredInitials } = body;

        if (!documentId || !documentTitle || !documentHash || !creator || !signers) {
          return sendJSON(res, 400, { success: false, error: "Missing required fields", timestamp: new Date().toISOString() });
        }

        const session = sessionEngine.createSession({
          documentId,
          documentTitle,
          documentHash,
          sku,
          creator,
          signers,
          threshold,
          requireAll,
          ordering,
          expiresInHours,
          requireOTP,
          requiredInitials,
          baseUrl: `http://${host}:${port}/sign`,
        });

        return sendJSON(res, 201, {
          success: true,
          data: {
            sessionId: session.sessionId,
            signingLinks: session.signers.map((s) => ({
              name: s.name,
              email: s.email,
              url: sessionEngine.getSigningUrl(session, s),
            })),
            expiresAt: session.config.expiresAt,
          },
          timestamp: new Date().toISOString(),
        });
      }

      // ── 404 ────────────────────────────────────────────────
      sendJSON(res, 404, { success: false, error: "Not found", timestamp: new Date().toISOString() });
    } catch (err: any) {
      console.error("[GATEWAY ERROR]", err.message);
      sendJSON(res, 500, { success: false, error: "Internal server error", timestamp: new Date().toISOString() });
    }
  });

  server.listen(port, host, () => {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SIGNING GATEWAY — ACTIVE");
    console.log("═══════════════════════════════════════════════════════");
    console.log(`  Dashboard:  http://${host}:${port}/`);
    console.log(`  Health:     http://${host}:${port}/health`);
    console.log(`  API:        POST http://${host}:${port}/session`);
    console.log("");
    console.log("  Signing links follow the pattern:");
    console.log(`    http://${host}:${port}/sign/<access_token>`);
    console.log("");
  });

  return server;
}

// ── Route Handlers ───────────────────────────────────────────

async function handleInitial(
  token: string,
  req: http.IncomingMessage,
  res: http.ServerResponse,
  sessionEngine: SigningSessionEngine,
  intentLogger: IntentLogger
): Promise<void> {
  const resolved = sessionEngine.resolveToken(token);
  if (!resolved) {
    return sendJSON(res, 403, { success: false, error: "Invalid token", timestamp: new Date().toISOString() });
  }

  const { session, signer } = resolved;
  const body = JSON.parse(await readBody(req));
  const { sectionId } = body;

  if (!sectionId) {
    return sendJSON(res, 400, { success: false, error: "Missing sectionId", timestamp: new Date().toISOString() });
  }

  const result = sessionEngine.recordInitial(session.sessionId, signer.signerId, sectionId);

  if (result.success) {
    intentLogger.log({
      sessionId: session.sessionId,
      documentId: session.documentId,
      signerId: signer.signerId,
      signerEmail: signer.email,
      signerName: signer.name,
      action: "section-initialed",
      ipAddress: getClientIP(req),
      device: getDeviceEvidence(req),
      sectionId,
    });
  }

  return sendJSON(res, result.success ? 200 : 400, {
    success: result.success,
    data: { message: result.message, remainingInitials: result.remainingInitials },
    error: result.success ? undefined : result.message,
    timestamp: new Date().toISOString(),
  });
}

async function handleOTPRequest(
  token: string,
  req: http.IncomingMessage,
  res: http.ServerResponse,
  sessionEngine: SigningSessionEngine,
  otpEngine: OTPEngine,
  intentLogger: IntentLogger
): Promise<void> {
  const resolved = sessionEngine.resolveToken(token);
  if (!resolved) {
    return sendJSON(res, 403, { success: false, error: "Invalid token", timestamp: new Date().toISOString() });
  }

  const { session, signer } = resolved;
  const result = otpEngine.generate({
    sessionId: session.sessionId,
    signerId: signer.signerId,
    signerEmail: signer.email,
    deliveryChannel: signer.channels[0] || "email",
    requestIp: getClientIP(req),
  });

  if ("error" in result) {
    return sendJSON(res, 429, { success: false, error: result.error, timestamp: new Date().toISOString() });
  }

  // Log OTP request
  intentLogger.log({
    sessionId: session.sessionId,
    documentId: session.documentId,
    signerId: signer.signerId,
    signerEmail: signer.email,
    signerName: signer.name,
    action: "otp-requested",
    ipAddress: getClientIP(req),
    device: getDeviceEvidence(req),
    context: { otpId: result.otpId, deliveryChannel: signer.channels[0] || "email" },
  });

  // In local mode, log the OTP code for testing
  console.log(`  [OTP] Code for ${signer.email}: ${result.code} (expires: ${result.expiresAt})`);

  return sendJSON(res, 200, {
    success: true,
    data: {
      message: "Verification code sent",
      expiresAt: result.expiresAt,
      isRetry: result.isRetry,
    },
    timestamp: new Date().toISOString(),
  });
}

async function handleOTPVerify(
  token: string,
  req: http.IncomingMessage,
  res: http.ServerResponse,
  sessionEngine: SigningSessionEngine,
  otpEngine: OTPEngine,
  intentLogger: IntentLogger
): Promise<void> {
  const resolved = sessionEngine.resolveToken(token);
  if (!resolved) {
    return sendJSON(res, 403, { success: false, error: "Invalid token", timestamp: new Date().toISOString() });
  }

  const { session, signer } = resolved;
  const body = JSON.parse(await readBody(req));
  const { code } = body;

  if (!code) {
    return sendJSON(res, 400, { success: false, error: "Missing OTP code", timestamp: new Date().toISOString() });
  }

  const result = otpEngine.verify({
    sessionId: session.sessionId,
    signerId: signer.signerId,
    code,
  });

  intentLogger.log({
    sessionId: session.sessionId,
    documentId: session.documentId,
    signerId: signer.signerId,
    signerEmail: signer.email,
    signerName: signer.name,
    action: result.valid ? "otp-verified" : "otp-failed",
    ipAddress: getClientIP(req),
    device: getDeviceEvidence(req),
    context: { otpId: result.otpId, remainingAttempts: String(result.remainingAttempts) },
  });

  return sendJSON(res, result.valid ? 200 : 400, {
    success: result.valid,
    data: { message: result.message, remainingAttempts: result.remainingAttempts },
    error: result.valid ? undefined : result.message,
    timestamp: new Date().toISOString(),
  });
}

async function handleSignature(
  token: string,
  req: http.IncomingMessage,
  res: http.ServerResponse,
  sessionEngine: SigningSessionEngine,
  intentLogger: IntentLogger
): Promise<void> {
  const resolved = sessionEngine.resolveToken(token);
  if (!resolved) {
    return sendJSON(res, 403, { success: false, error: "Invalid token", timestamp: new Date().toISOString() });
  }

  const { session, signer } = resolved;
  const body = JSON.parse(await readBody(req));
  const { consent, consentText } = body;

  // Verify consent
  if (session.config.requireIntent && !consent) {
    return sendJSON(res, 400, { success: false, error: "Consent checkbox required", timestamp: new Date().toISOString() });
  }

  // Verify OTP if required
  if (session.config.requireOTP) {
    const otpEngine = getOTPEngine();
    if (!otpEngine.isVerified(session.sessionId, signer.signerId)) {
      return sendJSON(res, 400, { success: false, error: "OTP verification required before signing", timestamp: new Date().toISOString() });
    }
  }

  // Log consent
  const ip = getClientIP(req);
  const device = getDeviceEvidence(req);

  intentLogger.logConsent({
    sessionId: session.sessionId,
    documentId: session.documentId,
    signerId: signer.signerId,
    signerEmail: signer.email,
    signerName: signer.name,
    ipAddress: ip,
    device,
    consent: {
      consentGiven: true,
      consentText: consentText || "Electronic signature consent",
      consentMethod: "checkbox",
      consentTimestamp: new Date().toISOString(),
      consentScope: `Sign document: ${session.documentTitle}`,
    },
  });

  // Compute signature hash
  const signatureEngine = getSignatureEngine();
  const sigState = signatureEngine.createSignatureState(session.documentId, session.documentHash);
  const signResult = signatureEngine.sign(sigState, {
    signer: {
      name: signer.name,
      email: signer.email,
      organization: signer.organization,
      role: signer.role,
      signatureType: signer.signatureType,
    },
    fingerprint: {
      sha256: session.documentHash,
      merkleRoot: session.documentHash,
      sourceHash: session.documentHash,
      timestamp: Date.now(),
      version: "1",
    },
  });

  const signatureHash = signResult.signatureHash;

  // Record in session
  const result = sessionEngine.recordSignature(
    session.sessionId,
    signer.signerId,
    signatureHash
  );

  // Log signature intent
  intentLogger.logSignature({
    sessionId: session.sessionId,
    documentId: session.documentId,
    signerId: signer.signerId,
    signerEmail: signer.email,
    signerName: signer.name,
    ipAddress: ip,
    device,
    consent: {
      consentGiven: true,
      consentText: consentText || "Electronic signature consent",
      consentMethod: "checkbox",
      consentTimestamp: new Date().toISOString(),
      consentScope: `Sign document: ${session.documentTitle}`,
    },
    signatureHash,
  });

  return sendJSON(res, result.success ? 200 : 400, {
    success: result.success,
    data: {
      message: result.message,
      signatureHash: result.success ? signatureHash : undefined,
      sessionStatus: result.sessionStatus,
      thresholdMet: result.thresholdMet,
    },
    error: result.success ? undefined : result.message,
    timestamp: new Date().toISOString(),
  });
}

// ── Error Page ───────────────────────────────────────────────

function renderErrorPage(title: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error — Signing Gateway</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .error-card { background: white; border-radius: 12px; padding: 48px; text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); max-width: 400px; }
    .error-card h1 { color: #ef4444; font-size: 20px; margin-bottom: 12px; }
    .error-card p { color: #666; font-size: 14px; }
  </style>
</head>
<body>
  <div class="error-card">
    <h1>${title}</h1>
    <p>${message}</p>
  </div>
</body>
</html>`;
}
