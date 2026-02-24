// ─────────────────────────────────────────────────────────────
// Cloudflare Perimeter — Configuration Engine
//
// Central configuration store for Cloudflare infrastructure:
//   • Subdomain mapping (money, sign, viewer, api)
//   • Tunnel configuration
//   • WAF rule definitions
//   • Rate limiting rules
//   • Bot protection settings
//   • Telnyx IP allowlist
//   • Geo-blocking rules
//   • Zero Trust access policies
//
// Deployment model: Local-first with Cloudflare Tunnel
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

/** Cloudflare proxy mode for subdomains */
export type ProxyMode = "proxied" | "dns-only" | "tunnel";

/** Service type behind Cloudflare */
export type ServiceType = "portal" | "gateway" | "viewer" | "webhook" | "api";

/** WAF action for matched rules */
export type WAFAction = "block" | "challenge" | "js_challenge" | "managed_challenge" | "log" | "allow";

/** Rate limit action */
export type RateLimitAction = "block" | "challenge" | "log";

/** Geo-blocking mode */
export type GeoMode = "allow-list" | "block-list" | "disabled";

/** Zero Trust access level */
export type AccessLevel = "public" | "authenticated" | "device-bound" | "mtls" | "internal-only";

/** Subdomain configuration */
export interface SubdomainConfig {
  /** Subdomain prefix (e.g., "money", "sign") */
  subdomain: string;
  /** Full domain (e.g., "money.fthtrading.com") */
  fullDomain: string;
  /** Service type this domain routes to */
  serviceType: ServiceType;
  /** Local port to route to */
  localPort: number;
  /** Local protocol */
  localProtocol: "http" | "https";
  /** Proxy mode */
  proxyMode: ProxyMode;
  /** TLS enforcement */
  tlsMode: "flexible" | "full" | "full-strict";
  /** Access level required */
  accessLevel: AccessLevel;
  /** Whether caching is enabled */
  cachingEnabled: boolean;
  /** Cache TTL in seconds (0 = no cache) */
  cacheTTL: number;
  /** Description */
  description: string;
}

/** WAF rule definition */
export interface WAFRule {
  /** Rule ID */
  ruleId: string;
  /** Rule name */
  name: string;
  /** Description */
  description: string;
  /** Expression (Cloudflare filter expression syntax) */
  expression: string;
  /** Action to take */
  action: WAFAction;
  /** Priority (lower = higher priority) */
  priority: number;
  /** Whether rule is enabled */
  enabled: boolean;
  /** Associated service */
  serviceType: ServiceType | "all";
}

/** Rate limit rule */
export interface RateLimitRule {
  /** Rule ID */
  ruleId: string;
  /** Rule name */
  name: string;
  /** Requests per period */
  requestsPerPeriod: number;
  /** Period in seconds */
  periodSeconds: number;
  /** Action when exceeded */
  action: RateLimitAction;
  /** Block duration in seconds */
  blockDurationSeconds: number;
  /** URL pattern to match */
  urlPattern: string;
  /** Associated service */
  serviceType: ServiceType | "all";
  /** Whether to count by IP */
  countByIP: boolean;
  /** Whether to count by token/header */
  countByHeader?: string;
}

/** IP allowlist entry */
export interface IPAllowlistEntry {
  /** CIDR or single IP */
  cidr: string;
  /** Label */
  label: string;
  /** Source (e.g., "telnyx", "internal") */
  source: string;
  /** When added */
  addedAt: string;
}

/** Geo-blocking rule */
export interface GeoRule {
  /** Country ISO codes */
  countries: string[];
  /** Mode */
  mode: GeoMode;
  /** Associated service */
  serviceType: ServiceType | "all";
  /** Description */
  description: string;
}

/** Tunnel ingress rule */
export interface TunnelIngress {
  /** Hostname to match */
  hostname: string;
  /** Local service URL */
  service: string;
  /** Path prefix (optional) */
  path?: string;
  /** Origin server name (for TLS) */
  originServerName?: string;
  /** No TLS verify for local */
  noTLSVerify: boolean;
}

/** Full tunnel configuration */
export interface TunnelConfig {
  /** Tunnel name */
  tunnelName: string;
  /** Tunnel ID (assigned by Cloudflare) */
  tunnelId: string;
  /** Credentials file path */
  credentialsFile: string;
  /** Ingress rules */
  ingress: TunnelIngress[];
  /** Metrics port for cloudflared */
  metricsPort: number;
  /** Log level */
  logLevel: "debug" | "info" | "warn" | "error" | "fatal";
  /** Protocol */
  protocol: "quic" | "http2" | "auto";
  /** Grace period for shutdown (seconds) */
  gracePeriodSeconds: number;
}

/** Full Cloudflare perimeter configuration */
export interface PerimeterConfig {
  /** Config version */
  version: string;
  /** Base domain */
  baseDomain: string;
  /** Cloudflare Account ID */
  accountId: string;
  /** Cloudflare Zone ID */
  zoneId: string;
  /** API token (stored separately, referenced here) */
  apiTokenRef: string;
  /** Subdomain configurations */
  subdomains: SubdomainConfig[];
  /** Tunnel configuration */
  tunnel: TunnelConfig;
  /** WAF rules */
  wafRules: WAFRule[];
  /** Rate limit rules */
  rateLimitRules: RateLimitRule[];
  /** IP allowlist */
  ipAllowlist: IPAllowlistEntry[];
  /** Geo-blocking rules */
  geoRules: GeoRule[];
  /** Bot fight mode enabled */
  botFightMode: boolean;
  /** Turnstile CAPTCHA for sensitive endpoints */
  turnstileEnabled: boolean;
  /** Created timestamp */
  createdAt: string;
  /** Last updated */
  updatedAt: string;
  /** Config hash */
  configHash: string;
}

// ── Telnyx IP Ranges ─────────────────────────────────────────
// Official Telnyx webhook source IPs — these are the ONLY IPs
// that should be able to reach the webhook endpoint.
// Ref: https://support.telnyx.com/en/articles/4305821

const TELNYX_IP_RANGES: IPAllowlistEntry[] = [
  { cidr: "64.233.172.0/24", label: "Telnyx Webhook Primary", source: "telnyx", addedAt: new Date().toISOString() },
  { cidr: "64.233.173.0/24", label: "Telnyx Webhook Secondary", source: "telnyx", addedAt: new Date().toISOString() },
  { cidr: "35.196.52.204/32", label: "Telnyx Webhook GCP-1", source: "telnyx", addedAt: new Date().toISOString() },
  { cidr: "35.245.84.50/32", label: "Telnyx Webhook GCP-2", source: "telnyx", addedAt: new Date().toISOString() },
  { cidr: "35.245.155.52/32", label: "Telnyx Webhook GCP-3", source: "telnyx", addedAt: new Date().toISOString() },
  { cidr: "35.190.163.158/32", label: "Telnyx Webhook GCP-4", source: "telnyx", addedAt: new Date().toISOString() },
  { cidr: "35.185.40.220/32", label: "Telnyx Webhook GCP-5", source: "telnyx", addedAt: new Date().toISOString() },
  { cidr: "127.0.0.1/32", label: "Localhost (development)", source: "internal", addedAt: new Date().toISOString() },
  { cidr: "::1/128", label: "Localhost IPv6 (development)", source: "internal", addedAt: new Date().toISOString() },
];

// ── Default Configuration Factory ────────────────────────────

export class CloudflareConfig {
  private config: PerimeterConfig;
  private storePath: string;

  constructor() {
    this.storePath = path.join(process.cwd(), ".doc-engine", "perimeter-config.json");
    this.config = this.load();
  }

  /**
   * Generate default perimeter configuration.
   */
  private generateDefault(): PerimeterConfig {
    const now = new Date().toISOString();

    const subdomains: SubdomainConfig[] = [
      {
        subdomain: "money",
        fullDomain: "money.fthtrading.com",
        serviceType: "portal",
        localPort: 3001,
        localProtocol: "http",
        proxyMode: "tunnel",
        tlsMode: "full-strict",
        accessLevel: "authenticated",
        cachingEnabled: false,
        cacheTTL: 0,
        description: "Sovereign Portal — Fund operations, deal management, command surface",
      },
      {
        subdomain: "sign",
        fullDomain: "sign.fthtrading.com",
        serviceType: "gateway",
        localPort: 3002,
        localProtocol: "http",
        proxyMode: "tunnel",
        tlsMode: "full-strict",
        accessLevel: "public",
        cachingEnabled: false,
        cacheTTL: 0,
        description: "Signing Gateway — Token-authenticated document signing",
      },
      {
        subdomain: "viewer",
        fullDomain: "viewer.fthtrading.com",
        serviceType: "viewer",
        localPort: 3003,
        localProtocol: "http",
        proxyMode: "tunnel",
        tlsMode: "full-strict",
        accessLevel: "authenticated",
        cachingEnabled: false,
        cacheTTL: 0,
        description: "Secure Viewer — Controlled document viewing with forensic watermarks",
      },
      {
        subdomain: "api",
        fullDomain: "api.fthtrading.com",
        serviceType: "webhook",
        localPort: 3004,
        localProtocol: "http",
        proxyMode: "tunnel",
        tlsMode: "full-strict",
        accessLevel: "public",
        cachingEnabled: false,
        cacheTTL: 0,
        description: "SCA Webhook — Telnyx inbound SMS/MMS endpoint",
      },
    ];

    const tunnel: TunnelConfig = {
      tunnelName: "fth-infra",
      tunnelId: "",
      credentialsFile: path.join(process.env.USERPROFILE || "", ".cloudflared", "fth-infra.json"),
      ingress: [
        ...subdomains.map((s) => ({
          hostname: s.fullDomain,
          service: `${s.localProtocol}://localhost:${s.localPort}`,
          noTLSVerify: true,
        })),
        {
          hostname: "",
          service: "http_status:404",
          noTLSVerify: false,
        },
      ],
      metricsPort: 3100,
      logLevel: "info",
      protocol: "quic",
      gracePeriodSeconds: 30,
    };

    const wafRules = this.generateDefaultWAFRules();
    const rateLimitRules = this.generateDefaultRateLimits();
    const geoRules = this.generateDefaultGeoRules();

    const config: PerimeterConfig = {
      version: "1.0.0",
      baseDomain: "fthtrading.com",
      accountId: "",
      zoneId: "",
      apiTokenRef: "CLOUDFLARE_API_TOKEN",
      subdomains,
      tunnel,
      wafRules,
      rateLimitRules,
      ipAllowlist: [...TELNYX_IP_RANGES],
      geoRules,
      botFightMode: true,
      turnstileEnabled: true,
      createdAt: now,
      updatedAt: now,
      configHash: "",
    };

    config.configHash = this.computeConfigHash(config);
    return config;
  }

  /**
   * Default WAF rules for all services.
   */
  private generateDefaultWAFRules(): WAFRule[] {
    return [
      {
        ruleId: "waf-001",
        name: "Block Non-Telnyx Webhook IPs",
        description: "Only allow Telnyx source IPs to reach the webhook endpoint",
        expression: '(http.host eq "api.fthtrading.com" and http.request.uri.path contains "/webhook" and not ip.src in {64.233.172.0/24 64.233.173.0/24 35.196.52.204 35.245.84.50 35.245.155.52 35.190.163.158 35.185.40.220 127.0.0.1})',
        action: "block",
        priority: 1,
        enabled: true,
        serviceType: "webhook",
      },
      {
        ruleId: "waf-002",
        name: "Block SQL Injection on Signing Gateway",
        description: "Prevent SQL injection attempts on signing endpoints",
        expression: '(http.host eq "sign.fthtrading.com" and http.request.uri.query contains "SELECT" or http.request.uri.query contains "UNION" or http.request.uri.query contains "DROP")',
        action: "block",
        priority: 2,
        enabled: true,
        serviceType: "gateway",
      },
      {
        ruleId: "waf-003",
        name: "Block Path Traversal",
        description: "Prevent directory traversal attacks across all services",
        expression: '(http.request.uri.path contains ".." or http.request.uri.path contains "%2e%2e")',
        action: "block",
        priority: 3,
        enabled: true,
        serviceType: "all",
      },
      {
        ruleId: "waf-004",
        name: "Challenge Suspicious User Agents",
        description: "Force challenge for known bot/scanner user agents",
        expression: '(http.user_agent contains "sqlmap" or http.user_agent contains "nikto" or http.user_agent contains "nmap" or http.user_agent contains "masscan" or http.user_agent contains "dirbuster")',
        action: "block",
        priority: 4,
        enabled: true,
        serviceType: "all",
      },
      {
        ruleId: "waf-005",
        name: "Block Empty User Agent",
        description: "Block requests with no user agent (likely automated)",
        expression: '(http.user_agent eq "" and not http.host eq "api.fthtrading.com")',
        action: "managed_challenge",
        priority: 5,
        enabled: true,
        serviceType: "all",
      },
      {
        ruleId: "waf-006",
        name: "Protect Signing Tokens",
        description: "Additional scrutiny for sign token URLs",
        expression: '(http.host eq "sign.fthtrading.com" and http.request.uri.path matches "^/sign/[a-f0-9]+" and http.request.method ne "GET")',
        action: "block",
        priority: 6,
        enabled: true,
        serviceType: "gateway",
      },
      {
        ruleId: "waf-007",
        name: "Block XSS Attempts",
        description: "Block common XSS attack patterns",
        expression: '(http.request.uri contains "<script" or http.request.uri contains "javascript:" or http.request.uri contains "onerror=")',
        action: "block",
        priority: 7,
        enabled: true,
        serviceType: "all",
      },
      {
        ruleId: "waf-008",
        name: "Managed Ruleset — OWASP Core",
        description: "Enable Cloudflare OWASP managed ruleset",
        expression: "true",
        action: "managed_challenge",
        priority: 100,
        enabled: true,
        serviceType: "all",
      },
    ];
  }

  /**
   * Default rate limiting rules.
   */
  private generateDefaultRateLimits(): RateLimitRule[] {
    return [
      {
        ruleId: "rl-001",
        name: "Webhook Rate Limit",
        requestsPerPeriod: 30,
        periodSeconds: 60,
        action: "block",
        blockDurationSeconds: 300,
        urlPattern: "/webhook/*",
        serviceType: "webhook",
        countByIP: true,
      },
      {
        ruleId: "rl-002",
        name: "Signing Link Rate Limit",
        requestsPerPeriod: 10,
        periodSeconds: 60,
        action: "challenge",
        blockDurationSeconds: 120,
        urlPattern: "/sign/*",
        serviceType: "gateway",
        countByIP: true,
      },
      {
        ruleId: "rl-003",
        name: "Viewer Access Rate Limit",
        requestsPerPeriod: 20,
        periodSeconds: 60,
        action: "challenge",
        blockDurationSeconds: 60,
        urlPattern: "/view/*",
        serviceType: "viewer",
        countByIP: true,
      },
      {
        ruleId: "rl-004",
        name: "Portal API Rate Limit",
        requestsPerPeriod: 60,
        periodSeconds: 60,
        action: "block",
        blockDurationSeconds: 120,
        urlPattern: "/api/*",
        serviceType: "portal",
        countByIP: true,
      },
      {
        ruleId: "rl-005",
        name: "Global Rate Limit",
        requestsPerPeriod: 120,
        periodSeconds: 60,
        action: "managed_challenge" as RateLimitAction,
        blockDurationSeconds: 60,
        urlPattern: "/*",
        serviceType: "all",
        countByIP: true,
      },
      {
        ruleId: "rl-006",
        name: "OTP Endpoint Rate Limit",
        requestsPerPeriod: 5,
        periodSeconds: 300,
        action: "block",
        blockDurationSeconds: 600,
        urlPattern: "/otp/*",
        serviceType: "gateway",
        countByIP: true,
      },
    ];
  }

  /**
   * Default geo-blocking rules.
   */
  private generateDefaultGeoRules(): GeoRule[] {
    return [
      {
        countries: ["US", "CA", "GB", "IE", "AU", "NZ", "SG", "CH", "DE", "NL", "KY", "BM", "VG", "JE", "GG"],
        mode: "allow-list",
        serviceType: "portal",
        description: "Sovereign Portal restricted to primary jurisdiction countries + key financial centers",
      },
      {
        countries: [],
        mode: "disabled",
        serviceType: "gateway",
        description: "Signing Gateway open globally (signers may be anywhere)",
      },
      {
        countries: [],
        mode: "disabled",
        serviceType: "webhook",
        description: "Webhook open (Telnyx IPs validated separately via WAF)",
      },
      {
        countries: [],
        mode: "disabled",
        serviceType: "viewer",
        description: "Secure Viewer open globally (access controlled by tokens)",
      },
    ];
  }

  // ── Config Operations ──────────────────────────────────────

  /**
   * Load config from disk or generate defaults.
   */
  private load(): PerimeterConfig {
    try {
      if (fs.existsSync(this.storePath)) {
        const raw = fs.readFileSync(this.storePath, "utf-8");
        return JSON.parse(raw);
      }
    } catch {
      // Corrupted — regenerate
    }
    return this.generateDefault();
  }

  /**
   * Save config to disk.
   */
  save(): void {
    this.config.updatedAt = new Date().toISOString();
    this.config.configHash = this.computeConfigHash(this.config);
    const dir = path.dirname(this.storePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.storePath, JSON.stringify(this.config, null, 2), "utf-8");
  }

  /**
   * Compute a hash of the configuration for integrity verification.
   */
  private computeConfigHash(config: PerimeterConfig): string {
    const hashInput = JSON.stringify({
      version: config.version,
      baseDomain: config.baseDomain,
      subdomains: config.subdomains,
      tunnel: config.tunnel,
      wafRules: config.wafRules,
      rateLimitRules: config.rateLimitRules,
      ipAllowlist: config.ipAllowlist,
      geoRules: config.geoRules,
    });
    return crypto.createHash("sha256").update(hashInput).digest("hex");
  }

  // ── Accessors ──────────────────────────────────────────────

  getConfig(): PerimeterConfig { return this.config; }
  getSubdomains(): SubdomainConfig[] { return this.config.subdomains; }
  getTunnel(): TunnelConfig { return this.config.tunnel; }
  getWAFRules(): WAFRule[] { return this.config.wafRules; }
  getRateLimits(): RateLimitRule[] { return this.config.rateLimitRules; }
  getIPAllowlist(): IPAllowlistEntry[] { return this.config.ipAllowlist; }
  getGeoRules(): GeoRule[] { return this.config.geoRules; }

  /**
   * Get subdomain config by service type.
   */
  getSubdomain(serviceType: ServiceType): SubdomainConfig | undefined {
    return this.config.subdomains.find((s) => s.serviceType === serviceType);
  }

  /**
   * Get public URL for a service.
   */
  getPublicUrl(serviceType: ServiceType): string {
    const sub = this.getSubdomain(serviceType);
    if (!sub) return `http://localhost:${this.getDefaultPort(serviceType)}`;
    return `https://${sub.fullDomain}`;
  }

  /**
   * Get default local port for a service type.
   */
  private getDefaultPort(serviceType: ServiceType): number {
    switch (serviceType) {
      case "portal": return 3001;
      case "gateway": return 3002;
      case "viewer": return 3003;
      case "webhook": return 3004;
      case "api": return 3004;
      default: return 3000;
    }
  }

  // ── Mutations ──────────────────────────────────────────────

  /**
   * Set Cloudflare account credentials.
   */
  setCredentials(accountId: string, zoneId: string): void {
    this.config.accountId = accountId;
    this.config.zoneId = zoneId;
    this.save();
  }

  /**
   * Set tunnel ID (after creating tunnel in Cloudflare).
   */
  setTunnelId(tunnelId: string): void {
    this.config.tunnel.tunnelId = tunnelId;
    this.save();
  }

  /**
   * Update base domain.
   */
  setBaseDomain(domain: string): void {
    this.config.baseDomain = domain;
    for (const sub of this.config.subdomains) {
      sub.fullDomain = `${sub.subdomain}.${domain}`;
    }
    // Rebuild tunnel ingress
    this.config.tunnel.ingress = [
      ...this.config.subdomains.map((s) => ({
        hostname: s.fullDomain,
        service: `${s.localProtocol}://localhost:${s.localPort}`,
        noTLSVerify: true,
      })),
      { hostname: "", service: "http_status:404", noTLSVerify: false },
    ];
    this.save();
  }

  /**
   * Add a custom IP to the allowlist.
   */
  addIPAllowlist(cidr: string, label: string, source: string): void {
    this.config.ipAllowlist.push({
      cidr,
      label,
      source,
      addedAt: new Date().toISOString(),
    });
    this.save();
  }

  /**
   * Remove IP from allowlist.
   */
  removeIPAllowlist(cidr: string): boolean {
    const before = this.config.ipAllowlist.length;
    this.config.ipAllowlist = this.config.ipAllowlist.filter((e) => e.cidr !== cidr);
    if (this.config.ipAllowlist.length !== before) {
      this.save();
      return true;
    }
    return false;
  }

  /**
   * Toggle a WAF rule.
   */
  toggleWAFRule(ruleId: string, enabled: boolean): boolean {
    const rule = this.config.wafRules.find((r) => r.ruleId === ruleId);
    if (!rule) return false;
    rule.enabled = enabled;
    this.save();
    return true;
  }

  /**
   * Update rate limit for a rule.
   */
  updateRateLimit(ruleId: string, requestsPerPeriod: number, periodSeconds: number): boolean {
    const rule = this.config.rateLimitRules.find((r) => r.ruleId === ruleId);
    if (!rule) return false;
    rule.requestsPerPeriod = requestsPerPeriod;
    rule.periodSeconds = periodSeconds;
    this.save();
    return true;
  }

  /**
   * Update access level for a subdomain.
   */
  setAccessLevel(serviceType: ServiceType, level: AccessLevel): boolean {
    const sub = this.config.subdomains.find((s) => s.serviceType === serviceType);
    if (!sub) return false;
    sub.accessLevel = level;
    this.save();
    return true;
  }

  // ── Export Helpers ─────────────────────────────────────────

  /**
   * Export cloudflared tunnel YAML configuration.
   */
  exportTunnelYAML(): string {
    const t = this.config.tunnel;
    const lines: string[] = [
      `# Cloudflare Tunnel Configuration — ${t.tunnelName}`,
      `# Generated by FTH Document Intelligence Engine`,
      `# ${new Date().toISOString()}`,
      ``,
      `tunnel: ${t.tunnelId || "YOUR_TUNNEL_ID"}`,
      `credentials-file: ${t.credentialsFile}`,
      ``,
      `metrics: localhost:${t.metricsPort}`,
      `loglevel: ${t.logLevel}`,
      `protocol: ${t.protocol}`,
      `grace-period: ${t.gracePeriodSeconds}s`,
      ``,
      `ingress:`,
    ];

    for (const rule of t.ingress) {
      if (rule.hostname) {
        lines.push(`  - hostname: ${rule.hostname}`);
        lines.push(`    service: ${rule.service}`);
        if (rule.noTLSVerify) {
          lines.push(`    originRequest:`);
          lines.push(`      noTLSVerify: true`);
        }
      } else {
        lines.push(`  - service: ${rule.service}`);
      }
    }

    return lines.join("\n");
  }

  /**
   * Export DNS records for Cloudflare API setup.
   */
  exportDNSRecords(): Array<{ type: string; name: string; content: string; proxied: boolean; ttl: number }> {
    const tunnelId = this.config.tunnel.tunnelId || "YOUR_TUNNEL_ID";
    return this.config.subdomains.map((s) => ({
      type: "CNAME",
      name: s.subdomain,
      content: `${tunnelId}.cfargotunnel.com`,
      proxied: s.proxyMode === "tunnel" || s.proxyMode === "proxied",
      ttl: 1, // Auto
    }));
  }

  /**
   * Format configuration summary for display.
   */
  formatSummary(): string {
    const c = this.config;
    const lines: string[] = [
      `  Cloudflare Perimeter Configuration v${c.version}`,
      `  ──────────────────────────────────────────────`,
      `  Base Domain:    ${c.baseDomain}`,
      `  Account ID:     ${c.accountId || "(not configured)"}`,
      `  Zone ID:        ${c.zoneId || "(not configured)"}`,
      `  Tunnel:         ${c.tunnel.tunnelName} (${c.tunnel.tunnelId || "not created"})`,
      `  Bot Fight Mode: ${c.botFightMode ? "ENABLED" : "disabled"}`,
      `  Turnstile:      ${c.turnstileEnabled ? "ENABLED" : "disabled"}`,
      `  Config Hash:    ${c.configHash.substring(0, 16)}...`,
      ``,
      `  Subdomains:`,
    ];

    for (const s of c.subdomains) {
      lines.push(`    ${s.fullDomain.padEnd(30)} → localhost:${s.localPort}  [${s.accessLevel}] ${s.description.substring(0, 40)}...`);
    }

    lines.push(``);
    lines.push(`  WAF Rules: ${c.wafRules.filter((r) => r.enabled).length}/${c.wafRules.length} active`);
    lines.push(`  Rate Limits: ${c.rateLimitRules.length} rules`);
    lines.push(`  IP Allowlist: ${c.ipAllowlist.length} entries`);
    lines.push(`  Geo Rules: ${c.geoRules.length} rules`);

    return lines.join("\n");
  }

  /**
   * Verify configuration integrity.
   */
  verifyIntegrity(): { valid: boolean; computedHash: string; storedHash: string } {
    const computed = this.computeConfigHash(this.config);
    return {
      valid: computed === this.config.configHash,
      computedHash: computed,
      storedHash: this.config.configHash,
    };
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: CloudflareConfig | null = null;
export function getCloudflareConfig(): CloudflareConfig {
  if (!_instance) _instance = new CloudflareConfig();
  return _instance;
}
