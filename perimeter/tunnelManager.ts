// ─────────────────────────────────────────────────────────────
// Cloudflare Perimeter — Tunnel Manager
//
// Manages Cloudflare Tunnel lifecycle:
//   • cloudflared process management
//   • Tunnel creation / deletion
//   • DNS route configuration
//   • Health monitoring
//   • Configuration file generation
//   • Tunnel status reporting
//
// Deployment: Local-first with cloudflared binary
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { exec, spawn, ChildProcess } from "child_process";
import { getCloudflareConfig, TunnelConfig, TunnelIngress } from "./cloudflareConfig";

// ── Types ────────────────────────────────────────────────────

/** Tunnel running state */
export type TunnelState = "stopped" | "starting" | "running" | "error" | "reconnecting";

/** Tunnel health check result */
export interface TunnelHealth {
  /** Current state */
  state: TunnelState;
  /** Whether cloudflared binary is found */
  binaryFound: boolean;
  /** cloudflared version (if available) */
  binaryVersion: string | null;
  /** Whether credentials file exists */
  credentialsExist: boolean;
  /** PID of running cloudflared process */
  pid: number | null;
  /** Uptime in seconds (if running) */
  uptimeSeconds: number | null;
  /** Last error message */
  lastError: string | null;
  /** Connected connectors */
  connectors: number;
  /** Metrics URL */
  metricsUrl: string;
  /** Ingress routes count */
  ingressRoutes: number;
  /** Checked at */
  checkedAt: string;
}

/** Tunnel event for logging */
export interface TunnelEvent {
  eventId: string;
  timestamp: string;
  event: "started" | "stopped" | "error" | "reconnected" | "config-changed" | "health-check" | "dns-updated";
  message: string;
  details?: Record<string, unknown>;
}

/** Service route status */
export interface RouteStatus {
  hostname: string;
  service: string;
  reachable: boolean;
  responseTime: number | null;
  lastChecked: string;
}

// ── Tunnel Manager ───────────────────────────────────────────

export class TunnelManager {
  private config = getCloudflareConfig();
  private state: TunnelState = "stopped";
  private cloudflaredProcess: ChildProcess | null = null;
  private startedAt: number | null = null;
  private lastError: string | null = null;
  private events: TunnelEvent[] = [];
  private configDir: string;

  constructor() {
    this.configDir = path.join(process.cwd(), ".doc-engine", "tunnel");
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true });
    }
  }

  // ── Configuration Generation ───────────────────────────────

  /**
   * Generate and write the cloudflared config YAML file.
   */
  generateConfigFile(): string {
    const yaml = this.config.exportTunnelYAML();
    const configPath = path.join(this.configDir, "config.yml");
    fs.writeFileSync(configPath, yaml, "utf-8");
    this.recordEvent("config-changed", `Configuration file generated at ${configPath}`);
    return configPath;
  }

  /**
   * Generate DNS CNAME records for Cloudflare setup.
   */
  generateDNSRecords(): string {
    const records = this.config.exportDNSRecords();
    const lines: string[] = [
      "# DNS Records for Cloudflare Tunnel",
      `# Tunnel: ${this.config.getTunnel().tunnelName}`,
      `# Generated: ${new Date().toISOString()}`,
      "",
      "# Add these CNAME records in Cloudflare DNS:",
      "",
    ];

    for (const r of records) {
      lines.push(`# ${r.name}.${this.config.getConfig().baseDomain}`);
      lines.push(`#   Type: ${r.type}`);
      lines.push(`#   Content: ${r.content}`);
      lines.push(`#   Proxied: ${r.proxied ? "Yes (orange cloud)" : "No (gray cloud)"}`);
      lines.push(`#   TTL: Auto`);
      lines.push("");
    }

    const dnsPath = path.join(this.configDir, "dns-records.txt");
    fs.writeFileSync(dnsPath, lines.join("\n"), "utf-8");
    this.recordEvent("dns-updated", `DNS record reference generated at ${dnsPath}`);
    return dnsPath;
  }

  // ── Tunnel Lifecycle ───────────────────────────────────────

  /**
   * Check if cloudflared binary is available.
   */
  async checkBinary(): Promise<{ found: boolean; version: string | null; path: string | null }> {
    return new Promise((resolve) => {
      exec("cloudflared --version", (error, stdout) => {
        if (error) {
          resolve({ found: false, version: null, path: null });
        } else {
          const version = stdout.trim();
          resolve({ found: true, version, path: "cloudflared" });
        }
      });
    });
  }

  /**
   * Start the cloudflared tunnel.
   * Requires: cloudflared binary installed, tunnel created, credentials configured.
   */
  async start(): Promise<{ success: boolean; message: string }> {
    if (this.state === "running") {
      return { success: false, message: "Tunnel is already running" };
    }

    const binary = await this.checkBinary();
    if (!binary.found) {
      this.lastError = "cloudflared binary not found. Install from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/";
      this.state = "error";
      this.recordEvent("error", this.lastError);
      return { success: false, message: this.lastError };
    }

    const tunnelConfig = this.config.getTunnel();
    if (!tunnelConfig.tunnelId) {
      this.lastError = "Tunnel ID not configured. Run: cloudflared tunnel create fth-infra";
      this.state = "error";
      this.recordEvent("error", this.lastError);
      return { success: false, message: this.lastError };
    }

    // Generate config file
    const configPath = this.generateConfigFile();

    // Start cloudflared
    this.state = "starting";
    this.recordEvent("started", `Starting tunnel ${tunnelConfig.tunnelName}`);

    try {
      this.cloudflaredProcess = spawn("cloudflared", [
        "tunnel",
        "--config", configPath,
        "run",
        tunnelConfig.tunnelName,
      ], {
        stdio: ["ignore", "pipe", "pipe"],
        detached: false,
      });

      this.cloudflaredProcess.on("error", (err) => {
        this.state = "error";
        this.lastError = err.message;
        this.recordEvent("error", `Process error: ${err.message}`);
      });

      this.cloudflaredProcess.on("exit", (code) => {
        this.state = "stopped";
        this.startedAt = null;
        this.recordEvent("stopped", `Tunnel process exited with code ${code}`);
      });

      // Monitor stdout for connection events
      if (this.cloudflaredProcess.stdout) {
        this.cloudflaredProcess.stdout.on("data", (data: Buffer) => {
          const line = data.toString().trim();
          if (line.includes("Registered tunnel connection")) {
            this.state = "running";
            if (!this.startedAt) this.startedAt = Date.now();
          }
          if (line.includes("Retrying connection")) {
            this.state = "reconnecting";
            this.recordEvent("reconnected", line);
          }
        });
      }

      if (this.cloudflaredProcess.stderr) {
        this.cloudflaredProcess.stderr.on("data", (data: Buffer) => {
          const line = data.toString().trim();
          if (line.includes("ERR")) {
            this.lastError = line;
          }
        });
      }

      this.state = "running";
      this.startedAt = Date.now();

      return {
        success: true,
        message: `Tunnel ${tunnelConfig.tunnelName} started (PID: ${this.cloudflaredProcess.pid})`,
      };
    } catch (err: any) {
      this.state = "error";
      this.lastError = err.message;
      this.recordEvent("error", `Failed to start: ${err.message}`);
      return { success: false, message: `Failed to start tunnel: ${err.message}` };
    }
  }

  /**
   * Stop the running tunnel.
   */
  stop(): { success: boolean; message: string } {
    if (!this.cloudflaredProcess || this.state === "stopped") {
      return { success: false, message: "Tunnel is not running" };
    }

    try {
      this.cloudflaredProcess.kill("SIGTERM");
      this.state = "stopped";
      this.startedAt = null;
      this.cloudflaredProcess = null;
      this.recordEvent("stopped", "Tunnel stopped by operator");
      return { success: true, message: "Tunnel stopped" };
    } catch (err: any) {
      return { success: false, message: `Failed to stop: ${err.message}` };
    }
  }

  // ── Health & Status ────────────────────────────────────────

  /**
   * Get comprehensive tunnel health status.
   */
  async getHealth(): Promise<TunnelHealth> {
    const binary = await this.checkBinary();
    const tunnelConfig = this.config.getTunnel();
    const credentialsExist = fs.existsSync(tunnelConfig.credentialsFile);

    return {
      state: this.state,
      binaryFound: binary.found,
      binaryVersion: binary.version,
      credentialsExist,
      pid: this.cloudflaredProcess?.pid || null,
      uptimeSeconds: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : null,
      lastError: this.lastError,
      connectors: this.state === "running" ? 4 : 0, // Cloudflare typically establishes 4 connectors
      metricsUrl: `http://localhost:${tunnelConfig.metricsPort}/metrics`,
      ingressRoutes: tunnelConfig.ingress.length - 1, // Exclude catch-all
      checkedAt: new Date().toISOString(),
    };
  }

  /**
   * Check if local services are reachable.
   */
  async checkRoutes(): Promise<RouteStatus[]> {
    const subdomains = this.config.getSubdomains();
    const results: RouteStatus[] = [];

    for (const sub of subdomains) {
      const start = Date.now();
      let reachable = false;

      try {
        // Simple TCP check
        const http = await import("http");
        await new Promise<void>((resolve, reject) => {
          const req = http.request({
            hostname: "localhost",
            port: sub.localPort,
            method: "HEAD",
            timeout: 3000,
          }, () => {
            reachable = true;
            resolve();
          });
          req.on("error", () => resolve());
          req.on("timeout", () => { req.destroy(); resolve(); });
          req.end();
        });
      } catch {
        // Not reachable
      }

      results.push({
        hostname: sub.fullDomain,
        service: `localhost:${sub.localPort}`,
        reachable,
        responseTime: reachable ? Date.now() - start : null,
        lastChecked: new Date().toISOString(),
      });
    }

    return results;
  }

  // ── Setup Assistance ───────────────────────────────────────

  /**
   * Generate step-by-step setup instructions.
   */
  generateSetupGuide(): string {
    const tunnelConfig = this.config.getTunnel();
    const subdomains = this.config.getSubdomains();

    const lines: string[] = [
      "═══════════════════════════════════════════════════════",
      "  CLOUDFLARE TUNNEL — SETUP GUIDE",
      "═══════════════════════════════════════════════════════",
      "",
      "  Step 1: Install cloudflared",
      "  ──────────────────────────────",
      "  Windows: winget install Cloudflare.cloudflared",
      "  macOS:   brew install cloudflare/cloudflare/cloudflared",
      "  Linux:   See https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/",
      "",
      "  Step 2: Authenticate",
      "  ──────────────────────────────",
      "  cloudflared tunnel login",
      "  (Opens browser for Cloudflare authentication)",
      "",
      "  Step 3: Create Tunnel",
      "  ──────────────────────────────",
      `  cloudflared tunnel create ${tunnelConfig.tunnelName}`,
      `  (Save the tunnel ID and update config)`,
      "",
      "  Step 4: Configure DNS",
      "  ──────────────────────────────",
    ];

    for (const sub of subdomains) {
      lines.push(`  cloudflared tunnel route dns ${tunnelConfig.tunnelName} ${sub.fullDomain}`);
    }

    lines.push("");
    lines.push("  Step 5: Run Tunnel");
    lines.push("  ──────────────────────────────");
    lines.push(`  npx ts-node app.ts --tunnel-start`);
    lines.push(`  OR manually: cloudflared tunnel --config ${path.join(this.configDir, "config.yml")} run ${tunnelConfig.tunnelName}`);
    lines.push("");
    lines.push("  Step 6: Verify");
    lines.push("  ──────────────────────────────");
    lines.push("  npx ts-node app.ts --tunnel-status");
    lines.push("  npx ts-node app.ts --perimeter-status");
    lines.push("");
    lines.push("  Service Mapping:");
    lines.push("  ──────────────────────────────");

    for (const sub of subdomains) {
      lines.push(`  https://${sub.fullDomain.padEnd(28)} → localhost:${sub.localPort}  (${sub.description.substring(0, 35)})`);
    }

    lines.push("");
    return lines.join("\n");
  }

  // ── Event Recording ────────────────────────────────────────

  private recordEvent(event: TunnelEvent["event"], message: string, details?: Record<string, unknown>): void {
    this.events.push({
      eventId: crypto.randomBytes(8).toString("hex"),
      timestamp: new Date().toISOString(),
      event,
      message,
      details,
    });
    // Keep last 500 events
    if (this.events.length > 500) {
      this.events = this.events.slice(-500);
    }
  }

  getEvents(): TunnelEvent[] { return [...this.events]; }
  getState(): TunnelState { return this.state; }

  /**
   * Format status for CLI display.
   */
  async formatStatus(): Promise<string> {
    const health = await this.getHealth();
    const routes = await this.checkRoutes();

    const lines: string[] = [
      `  Tunnel: ${this.config.getTunnel().tunnelName}`,
      `  State: ${health.state.toUpperCase()}`,
      `  Binary: ${health.binaryFound ? health.binaryVersion : "NOT FOUND"}`,
      `  Credentials: ${health.credentialsExist ? "FOUND" : "MISSING"}`,
      `  PID: ${health.pid || "N/A"}`,
      `  Uptime: ${health.uptimeSeconds ? `${health.uptimeSeconds}s` : "N/A"}`,
      `  Connectors: ${health.connectors}`,
      `  Metrics: ${health.metricsUrl}`,
      ``,
      `  Routes:`,
    ];

    for (const r of routes) {
      const status = r.reachable ? "UP" : "DOWN";
      const time = r.responseTime ? `${r.responseTime}ms` : "N/A";
      lines.push(`    ${r.hostname.padEnd(30)} → ${r.service.padEnd(16)} [${status}] ${time}`);
    }

    if (health.lastError) {
      lines.push(``);
      lines.push(`  Last Error: ${health.lastError}`);
    }

    return lines.join("\n");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: TunnelManager | null = null;
export function getTunnelManager(): TunnelManager {
  if (!_instance) _instance = new TunnelManager();
  return _instance;
}
