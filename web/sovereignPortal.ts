// ─────────────────────────────────────────────────────────────
// Sovereign Portal — Minimal HTTP Signing & Verification Server
//
// Endpoints:
//   GET  /                       Portal dashboard
//   GET  /verify/:documentId     Verify document integrity & signatures
//   GET  /verify/cid/:cid        Verify IPFS CID integrity
//   POST /sign/:documentId       Submit a signature for pending workflow
//   GET  /status/:workflowId     Multi-sig workflow status
//   POST /token                  Generate temporary access token
//   GET  /health                 Health check
//
// Tokens:
//   All write operations require a bearer token.
//   Tokens are ephemeral, in-memory, time-limited.
//
// ─────────────────────────────────────────────────────────────

import http from "http";
import crypto from "crypto";
import { getMultiSigEngine } from "../signature/multiSigWorkflow";
import { getSignatureEngine, SignerIdentity, DigitalSignature } from "../signature/signatureEngine";
import { getLifecycleRegistry } from "../sovereign/lifecycleRegistry";
import { getRegistry } from "../registry/cidRegistry";

// ── Types ────────────────────────────────────────────────────

interface AccessToken {
  token: string;
  email: string;
  purpose: "sign" | "verify" | "admin";
  createdAt: number;
  expiresAt: number;
  used: boolean;
}

interface PortalConfig {
  port: number;
  host: string;
  tokenTTL: number; // minutes
  maxTokens: number;
}

interface PortalResponse {
  success: boolean;
  data?: any;
  error?: string;
  timestamp: string;
}

// ── Token Store ──────────────────────────────────────────────

class TokenStore {
  private tokens: Map<string, AccessToken> = new Map();
  private maxTokens: number;
  private ttlMs: number;

  constructor(maxTokens: number = 100, ttlMinutes: number = 30) {
    this.maxTokens = maxTokens;
    this.ttlMs = ttlMinutes * 60 * 1000;
  }

  generate(email: string, purpose: "sign" | "verify" | "admin"): AccessToken {
    // Prune expired tokens
    this.prune();

    if (this.tokens.size >= this.maxTokens) {
      throw new Error("Token limit reached — prune or wait for expiration");
    }

    const token: AccessToken = {
      token: crypto.randomBytes(32).toString("hex"),
      email,
      purpose,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.ttlMs,
      used: false,
    };

    this.tokens.set(token.token, token);
    return token;
  }

  validate(bearerToken: string, requiredPurpose: "sign" | "verify" | "admin"): AccessToken | null {
    const token = this.tokens.get(bearerToken);
    if (!token) return null;
    if (Date.now() > token.expiresAt) {
      this.tokens.delete(bearerToken);
      return null;
    }
    if (token.purpose !== requiredPurpose && token.purpose !== "admin") {
      return null;
    }
    return token;
  }

  markUsed(bearerToken: string): void {
    const token = this.tokens.get(bearerToken);
    if (token) token.used = true;
  }

  prune(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [key, token] of this.tokens) {
      if (now > token.expiresAt) {
        this.tokens.delete(key);
        pruned++;
      }
    }
    return pruned;
  }

  getStats(): { active: number; expired: number; used: number } {
    this.prune();
    let used = 0;
    for (const token of this.tokens.values()) {
      if (token.used) used++;
    }
    return { active: this.tokens.size, expired: 0, used };
  }
}

// ── Request Helpers ──────────────────────────────────────────

function sendJSON(res: http.ServerResponse, status: number, body: PortalResponse): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(JSON.stringify(body, null, 2));
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function extractBearerToken(req: http.IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return null;
  return auth.substring(7);
}

function parseRoute(pathname: string): { route: string; params: string[] } {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 0) return { route: "/", params: [] };
  return { route: `/${parts[0]}`, params: parts.slice(1) };
}

// ── Portal Server ────────────────────────────────────────────

export function startSovereignPortal(config: Partial<PortalConfig> = {}): http.Server {
  const port = config.port || 3001;
  const host = config.host || "127.0.0.1";
  const tokenStore = new TokenStore(config.maxTokens || 100, config.tokenTTL || 30);

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
        return serveDashboard(res);
      }

      // ── GET /health — Health check ─────────────────────────
      if (method === "GET" && route === "/health") {
        return sendJSON(res, 200, {
          success: true,
          data: {
            status: "operational",
            tokens: tokenStore.getStats(),
            uptime: process.uptime(),
          },
          timestamp: new Date().toISOString(),
        });
      }

      // ── POST /token — Generate access token ────────────────
      if (method === "POST" && route === "/token") {
        const body = JSON.parse(await readBody(req));
        const { email, purpose } = body;
        if (!email || !purpose) {
          return sendJSON(res, 400, {
            success: false,
            error: "Missing required fields: email, purpose (sign|verify|admin)",
            timestamp: new Date().toISOString(),
          });
        }
        const token = tokenStore.generate(email, purpose);
        return sendJSON(res, 201, {
          success: true,
          data: {
            token: token.token,
            expiresAt: new Date(token.expiresAt).toISOString(),
            purpose: token.purpose,
          },
          timestamp: new Date().toISOString(),
        });
      }

      // ── GET /verify/:documentId — Verify document ──────────
      if (method === "GET" && route === "/verify" && params.length >= 1) {
        // Check if verifying by CID or document ID
        if (params[0] === "cid" && params.length >= 2) {
          return handleVerifyCID(params[1], res);
        }
        return handleVerifyDocument(params[0], res);
      }

      // ── GET /status/:workflowId — Workflow status ──────────
      if (method === "GET" && route === "/status" && params.length >= 1) {
        return handleWorkflowStatus(params[0], res);
      }

      // ── POST /sign/:documentId — Submit signature ──────────
      if (method === "POST" && route === "/sign" && params.length >= 1) {
        const bearer = extractBearerToken(req);
        if (!bearer) {
          return sendJSON(res, 401, {
            success: false,
            error: "Authorization required — Bearer token",
            timestamp: new Date().toISOString(),
          });
        }
        const tokenVal = tokenStore.validate(bearer, "sign");
        if (!tokenVal) {
          return sendJSON(res, 403, {
            success: false,
            error: "Invalid or expired token",
            timestamp: new Date().toISOString(),
          });
        }

        const body = JSON.parse(await readBody(req));
        const result = await handleSign(params[0], body, tokenVal);
        tokenStore.markUsed(bearer);
        return sendJSON(res, result.success ? 200 : 400, {
          success: result.success,
          data: result,
          timestamp: new Date().toISOString(),
        });
      }

      // ── 404 ────────────────────────────────────────────────
      sendJSON(res, 404, {
        success: false,
        error: `Not found: ${method} ${url.pathname}`,
        timestamp: new Date().toISOString(),
      });

    } catch (err: any) {
      console.error(`[PORTAL] Error: ${err.message}`);
      sendJSON(res, 500, {
        success: false,
        error: err.message || "Internal server error",
        timestamp: new Date().toISOString(),
      });
    }
  });

  server.listen(port, host, () => {
    console.log(`[PORTAL] Sovereign Portal listening on http://${host}:${port}`);
    console.log(`[PORTAL] Endpoints:`);
    console.log(`  GET  /                     Dashboard`);
    console.log(`  GET  /health               Health check`);
    console.log(`  POST /token                Generate access token`);
    console.log(`  GET  /verify/:documentId   Verify document`);
    console.log(`  GET  /verify/cid/:cid      Verify IPFS CID`);
    console.log(`  POST /sign/:documentId     Submit signature (requires token)`);
    console.log(`  GET  /status/:workflowId   Multi-sig workflow status`);
  });

  return server;
}

// ── Route Handlers ───────────────────────────────────────────

function handleVerifyDocument(documentId: string, res: http.ServerResponse): void {
  const lcRegistry = getLifecycleRegistry();
  const lifecycle = lcRegistry.getLifecycle(documentId);

  if (!lifecycle) {
    // Try partial match
    const all = lcRegistry.getAllLifecycles();
    const match = all.find(lc => lc.documentId.startsWith(documentId));
    if (!match) {
      return sendJSON(res, 404, {
        success: false,
        error: `Document not found: ${documentId}`,
        timestamp: new Date().toISOString(),
      });
    }
    return sendVerification(match, res);
  }

  return sendVerification(lifecycle, res);
}

function sendVerification(lifecycle: any, res: http.ServerResponse): void {
  const lcRegistry = getLifecycleRegistry();
  const integrityReport = lcRegistry.verifyIntegrity(lifecycle.documentId);

  sendJSON(res, 200, {
    success: true,
    data: {
      documentId: lifecycle.documentId,
      title: lifecycle.title,
      sku: lifecycle.sku,
      currentStage: lifecycle.currentStage,
      version: lifecycle.version,
      transitions: lifecycle.transitions.length,
      integrity: integrityReport,
      hashes: {
        draft: lifecycle.draftHash,
        signed: lifecycle.signedHash,
        current: lifecycle.currentHash,
      },
      cids: {
        plain: lifecycle.plainCID,
        encrypted: lifecycle.encryptedCID,
      },
      ledgerTx: lifecycle.ledgerTx,
    },
    timestamp: new Date().toISOString(),
  });
}

function handleVerifyCID(cid: string, res: http.ServerResponse): void {
  const registry = getRegistry();
  const lookup = registry.lookupByCID(cid);

  if (!lookup.found || !lookup.record) {
    return sendJSON(res, 404, {
      success: false,
      error: `CID not found in registry: ${cid}`,
      timestamp: new Date().toISOString(),
    });
  }

  const entry = lookup.record;
  sendJSON(res, 200, {
    success: true,
    data: {
      cid: entry.cid,
      sha256: entry.sha256,
      merkleRoot: entry.merkleRoot,
      sku: entry.sku,
      sourceFile: entry.sourceFile,
      registeredAt: entry.registeredAt,
      verified: true,
    },
    timestamp: new Date().toISOString(),
  });
}

function handleWorkflowStatus(workflowId: string, res: http.ServerResponse): void {
  const msEngine = getMultiSigEngine();
  const workflow = msEngine.getWorkflow(workflowId);

  if (!workflow) {
    // Try active workflows with partial match
    const active = msEngine.getActiveWorkflows();
    const match = active.find(w => w.workflowId.startsWith(workflowId));
    if (!match) {
      return sendJSON(res, 404, {
        success: false,
        error: `Workflow not found: ${workflowId}`,
        timestamp: new Date().toISOString(),
      });
    }
    return sendWorkflowData(match, res);
  }

  return sendWorkflowData(workflow, res);
}

function sendWorkflowData(workflow: any, res: http.ServerResponse): void {
  sendJSON(res, 200, {
    success: true,
    data: {
      workflowId: workflow.workflowId,
      documentId: workflow.documentId,
      status: workflow.status,
      threshold: workflow.config.requiredSignatures,
      signatureCount: workflow.signatureCount,
      thresholdMet: workflow.thresholdMet,
      counterparties: workflow.counterparties.map((cp: any) => ({
        email: cp.email,
        name: cp.name,
        role: cp.role,
        signed: !!cp.signedAt,
        rejected: !!cp.rejectedAt,
      })),
      createdAt: workflow.createdAt,
      finalizedAt: workflow.finalizedAt,
    },
    timestamp: new Date().toISOString(),
  });
}

async function handleSign(
  documentId: string,
  body: any,
  token: AccessToken
): Promise<{ success: boolean; message: string; [key: string]: any }> {
  const { workflowId, name, role, deviceFingerprint } = body;

  if (!workflowId) {
    return { success: false, message: "Missing workflowId in request body" };
  }

  const msEngine = getMultiSigEngine();
  const workflow = msEngine.getWorkflow(workflowId);
  if (!workflow) {
    return { success: false, message: `Workflow not found: ${workflowId}` };
  }

  if (workflow.documentId !== documentId &&
      !workflow.documentId.startsWith(documentId)) {
    return { success: false, message: "Document ID does not match workflow" };
  }

  // Construct signature
  const sigEngine = getSignatureEngine();
  const signatureId = crypto.randomBytes(16).toString("hex");
  const now = new Date().toISOString();

  const signer: SignerIdentity = {
    name: name || token.email.split("@")[0],
    email: token.email,
    role: role || "counterparty",
    signatureType: "counterparty",
  };

  const signatureHash = crypto
    .createHash("sha256")
    .update([
      signatureId,
      signer.name,
      signer.email,
      signer.role,
      signer.signatureType,
      workflow.documentHash,
      now,
      deviceFingerprint || "portal",
    ].join("|"))
    .digest("hex");

  const combinedHash = crypto
    .createHash("sha256")
    .update(workflow.documentHash + signatureHash)
    .digest("hex");

  const signature: DigitalSignature = {
    signatureId,
    signer,
    signedAt: now,
    documentHash: workflow.documentHash,
    signatureHash,
    combinedHash,
    status: "signed",
    deviceFingerprint: deviceFingerprint || "portal-browser",
    platform: "sovereign-portal",
    sequence: workflow.signatureCount + 1,
    previousSignatureHash: workflow.signatureCount > 0
      ? Object.values(workflow.signatures as Record<string, DigitalSignature>).pop()?.signatureHash || ""
      : "",
  };

  const result = msEngine.addSignature(workflowId, signature);

  // Auto-finalize if threshold met
  if (result.thresholdMet && result.workflowStatus !== "finalized") {
    msEngine.finalize(workflowId);
  }

  return {
    success: result.success,
    message: result.message,
    workflowStatus: result.workflowStatus,
    signatureCount: result.signatureCount,
    threshold: result.threshold,
    thresholdMet: result.thresholdMet,
    signatureHash,
  };
}

// ── Dashboard HTML ───────────────────────────────────────────

function serveDashboard(res: http.ServerResponse): void {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sovereign Document Portal</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
           background: #0a0a0a; color: #e0e0e0; padding: 2rem; }
    h1 { color: #00d4aa; margin-bottom: 0.5rem; font-size: 1.5rem; }
    h2 { color: #888; font-size: 0.9rem; font-weight: 400; margin-bottom: 2rem; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 8px;
            padding: 1.5rem; margin-bottom: 1rem; }
    .card h3 { color: #00d4aa; margin-bottom: 0.8rem; font-size: 1rem; }
    code { background: #222; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }
    .endpoint { display: flex; gap: 0.8rem; align-items: center; margin-bottom: 0.5rem; }
    .method { font-weight: bold; min-width: 4rem; text-align: center;
              padding: 0.2rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }
    .get { background: #1a472a; color: #4ade80; }
    .post { background: #472a1a; color: #fb923c; }
    .path { color: #93c5fd; font-family: monospace; }
    .desc { color: #888; font-size: 0.85rem; }
    .status { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 12px;
              font-size: 0.75rem; font-weight: bold; }
    .status.online { background: #1a472a; color: #4ade80; }
    footer { margin-top: 2rem; color: #555; font-size: 0.75rem; text-align: center; }
  </style>
</head>
<body>
  <h1>Sovereign Document Portal</h1>
  <h2>Document Intelligence Engine — Signing & Verification Gateway</h2>

  <div class="card">
    <h3>Status <span class="status online">ONLINE</span></h3>
    <p>Portal is operational. All verification and signing endpoints are active.</p>
  </div>

  <div class="card">
    <h3>API Endpoints</h3>
    <div class="endpoint">
      <span class="method get">GET</span>
      <span class="path">/health</span>
      <span class="desc">Health check & token stats</span>
    </div>
    <div class="endpoint">
      <span class="method post">POST</span>
      <span class="path">/token</span>
      <span class="desc">Generate access token {email, purpose}</span>
    </div>
    <div class="endpoint">
      <span class="method get">GET</span>
      <span class="path">/verify/:documentId</span>
      <span class="desc">Verify document integrity</span>
    </div>
    <div class="endpoint">
      <span class="method get">GET</span>
      <span class="path">/verify/cid/:cid</span>
      <span class="desc">Verify IPFS CID</span>
    </div>
    <div class="endpoint">
      <span class="method post">POST</span>
      <span class="path">/sign/:documentId</span>
      <span class="desc">Submit signature (requires Bearer token)</span>
    </div>
    <div class="endpoint">
      <span class="method get">GET</span>
      <span class="path">/status/:workflowId</span>
      <span class="desc">Multi-sig workflow status</span>
    </div>
  </div>

  <div class="card">
    <h3>Signing Flow</h3>
    <ol style="padding-left: 1.2rem; line-height: 1.8;">
      <li>Request a token: <code>POST /token</code> with <code>{"email":"...", "purpose":"sign"}</code></li>
      <li>Submit signature: <code>POST /sign/:docId</code> with Bearer token + <code>{"workflowId":"..."}</code></li>
      <li>Check status: <code>GET /status/:workflowId</code></li>
    </ol>
  </div>

  <footer>
    Document Intelligence Engine v5.0.0 — Sovereign Portal
  </footer>
</body>
</html>`;

  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(html);
}
