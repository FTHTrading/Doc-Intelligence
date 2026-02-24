// ─────────────────────────────────────────────────────────────
// IPFS Client — Sovereign IPFS Node Integration (Kubo RPC)
// ─────────────────────────────────────────────────────────────
//
// Connects directly to your local Kubo IPFS node via HTTP RPC.
// No third-party gateway required. Fully sovereign pipeline.
//
// Requires: Kubo running at localhost:5001
//   kubo daemon --api /ip4/127.0.0.1/tcp/5001
//
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import http from "http";
import https from "https";

export interface IPFSConfig {
  apiUrl: string;        // e.g. "http://127.0.0.1:5001"
  gatewayUrl: string;    // e.g. "http://127.0.0.1:8081"
  pinByDefault: boolean;
  timeout: number;       // ms
}

export interface IPFSAddResult {
  cid: string;           // Content Identifier (e.g. Qm... or bafy...)
  size: number;
  name: string;
}

export interface IPFSPinResult {
  cid: string;
  pinned: boolean;
}

export interface IPFSNodeInfo {
  id: string;
  publicKey: string;
  addresses: string[];
  agentVersion: string;
  protocolVersion: string;
}

/** Default config for local Kubo node */
export const DEFAULT_IPFS_CONFIG: IPFSConfig = {
  apiUrl: "http://127.0.0.1:5001",
  gatewayUrl: "http://127.0.0.1:8081",
  pinByDefault: true,
  timeout: 30000,
};

/**
 * IPFS Client — direct Kubo RPC integration
 */
export class IPFSClient {
  private config: IPFSConfig;

  constructor(config?: Partial<IPFSConfig>) {
    this.config = { ...DEFAULT_IPFS_CONFIG, ...config };
  }

  /**
   * Check if IPFS node is reachable.
   */
  async isOnline(): Promise<boolean> {
    try {
      await this.rpcGet("/api/v0/version");
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get node identity and peer info.
   */
  async getNodeInfo(): Promise<IPFSNodeInfo> {
    const result = await this.rpcPost("/api/v0/id");
    return {
      id: result.ID,
      publicKey: result.PublicKey,
      addresses: result.Addresses || [],
      agentVersion: result.AgentVersion,
      protocolVersion: result.ProtocolVersion,
    };
  }

  /**
   * Add a file to IPFS and return its CID.
   */
  async addFile(filePath: string): Promise<IPFSAddResult> {
    const absolutePath = path.resolve(filePath);
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`File not found: ${absolutePath}`);
    }

    const fileContent = fs.readFileSync(absolutePath);
    const fileName = path.basename(absolutePath);

    return this.addBuffer(fileContent, fileName);
  }

  /**
   * Add a buffer/string to IPFS and return its CID.
   */
  async addBuffer(content: Buffer | string, name = "document"): Promise<IPFSAddResult> {
    const buffer = typeof content === "string" ? Buffer.from(content, "utf-8") : content;

    // Build multipart/form-data manually (no external dependencies)
    const boundary = `----IPFSBoundary${Date.now()}${Math.random().toString(36)}`;
    const header = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${name}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`
    );
    const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([header, buffer, footer]);

    const result = await this.rpcPostMultipart("/api/v0/add?pin=true&quieter=false", body, boundary);

    return {
      cid: result.Hash,
      size: parseInt(result.Size, 10) || buffer.length,
      name: result.Name || name,
    };
  }

  /**
   * Add a JSON object to IPFS.
   */
  async addJSON(data: any, name = "data.json"): Promise<IPFSAddResult> {
    const json = JSON.stringify(data, null, 2);
    return this.addBuffer(Buffer.from(json, "utf-8"), name);
  }

  /**
   * Add an entire directory of files to IPFS.
   * Returns CID for each file + the wrapping directory CID.
   */
  async addDirectory(dirPath: string): Promise<{ files: IPFSAddResult[]; directoryCid: string }> {
    const absoluteDir = path.resolve(dirPath);
    if (!fs.existsSync(absoluteDir)) {
      throw new Error(`Directory not found: ${absoluteDir}`);
    }

    const files = fs.readdirSync(absoluteDir)
      .filter((f) => fs.statSync(path.join(absoluteDir, f)).isFile());

    // Build multipart body with all files
    const boundary = `----IPFSBoundary${Date.now()}${Math.random().toString(36)}`;
    const parts: Buffer[] = [];

    for (const file of files) {
      const content = fs.readFileSync(path.join(absoluteDir, file));
      const partHeader = Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="${file}"\r\n` +
        `Content-Type: application/octet-stream\r\n\r\n`
      );
      parts.push(partHeader, content, Buffer.from("\r\n"));
    }
    parts.push(Buffer.from(`--${boundary}--\r\n`));

    const body = Buffer.concat(parts);
    const rawResult = await this.rpcPostMultipartRaw(
      "/api/v0/add?pin=true&wrap-with-directory=true",
      body,
      boundary
    );

    // IPFS returns one JSON object per line (NDJSON)
    const lines = rawResult.trim().split("\n").map((l: string) => JSON.parse(l));
    const fileResults: IPFSAddResult[] = [];
    let directoryCid = "";

    for (const line of lines) {
      if (line.Name === "") {
        directoryCid = line.Hash;
      } else {
        fileResults.push({
          cid: line.Hash,
          size: parseInt(line.Size, 10) || 0,
          name: line.Name,
        });
      }
    }

    return { files: fileResults, directoryCid };
  }

  /**
   * Pin a CID to ensure it persists on your node.
   */
  async pin(cid: string): Promise<IPFSPinResult> {
    try {
      const result = await this.rpcPost(`/api/v0/pin/add?arg=${cid}`);
      return { cid, pinned: true };
    } catch (err: any) {
      return { cid, pinned: false };
    }
  }

  /**
   * Unpin a CID (allow garbage collection).
   */
  async unpin(cid: string): Promise<IPFSPinResult> {
    try {
      await this.rpcPost(`/api/v0/pin/rm?arg=${cid}`);
      return { cid, pinned: false };
    } catch {
      return { cid, pinned: true };
    }
  }

  /**
   * List all pinned CIDs.
   */
  async listPins(): Promise<string[]> {
    const result = await this.rpcPost("/api/v0/pin/ls?type=recursive");
    return Object.keys(result.Keys || {});
  }

  /**
   * Retrieve content from IPFS by CID.
   */
  async cat(cid: string): Promise<Buffer> {
    return this.rpcPostBuffer(`/api/v0/cat?arg=${cid}`);
  }

  /**
   * Get IPFS stats for node.
   */
  async getStats(): Promise<{ repoSize: number; numObjects: number; storageMax: number }> {
    const result = await this.rpcPost("/api/v0/repo/stat");
    return {
      repoSize: result.RepoSize || 0,
      numObjects: result.NumObjects || 0,
      storageMax: result.StorageMax || 0,
    };
  }

  /**
   * Get the public gateway URL for a CID.
   */
  getGatewayUrl(cid: string): string {
    return `${this.config.gatewayUrl}/ipfs/${cid}`;
  }

  /**
   * Get the IPFS protocol URL for a CID.
   */
  getIPFSUrl(cid: string): string {
    return `ipfs://${cid}`;
  }

  // ── HTTP Helpers ────────────────────────────────────────────

  private rpcGet(endpoint: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.config.apiUrl);
      const client = url.protocol === "https:" ? https : http;

      const req = client.get(url.toString(), { timeout: this.config.timeout }, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try { resolve(JSON.parse(data)); }
          catch { resolve(data); }
        });
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("IPFS request timeout")); });
    });
  }

  private rpcPost(endpoint: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.config.apiUrl);
      const client = url.protocol === "https:" ? https : http;

      const req = client.request(url.toString(), {
        method: "POST",
        timeout: this.config.timeout,
      }, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try { resolve(JSON.parse(data)); }
          catch { resolve(data); }
        });
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("IPFS request timeout")); });
      req.end();
    });
  }

  private rpcPostMultipart(endpoint: string, body: Buffer, boundary: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.config.apiUrl);
      const client = url.protocol === "https:" ? https : http;

      const req = client.request(url.toString(), {
        method: "POST",
        headers: {
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
          "Content-Length": body.length,
        },
        timeout: this.config.timeout,
      }, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            // Handle NDJSON — take last valid JSON line
            const lines = data.trim().split("\n");
            resolve(JSON.parse(lines[lines.length - 1]));
          } catch { resolve(data); }
        });
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("IPFS request timeout")); });
      req.write(body);
      req.end();
    });
  }

  private rpcPostMultipartRaw(endpoint: string, body: Buffer, boundary: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.config.apiUrl);
      const client = url.protocol === "https:" ? https : http;

      const req = client.request(url.toString(), {
        method: "POST",
        headers: {
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
          "Content-Length": body.length,
        },
        timeout: this.config.timeout,
      }, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data));
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("IPFS request timeout")); });
      req.write(body);
      req.end();
    });
  }

  private rpcPostBuffer(endpoint: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.config.apiUrl);
      const client = url.protocol === "https:" ? https : http;

      const req = client.request(url.toString(), {
        method: "POST",
        timeout: this.config.timeout,
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("IPFS request timeout")); });
      req.end();
    });
  }
}

/** Singleton instance */
let _defaultClient: IPFSClient | null = null;

export function getIPFSClient(config?: Partial<IPFSConfig>): IPFSClient {
  if (!_defaultClient || config) {
    _defaultClient = new IPFSClient(config);
  }
  return _defaultClient;
}
