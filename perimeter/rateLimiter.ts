// ─────────────────────────────────────────────────────────────
// Cloudflare Perimeter — Application Rate Limiter
//
// Defense-in-depth rate limiting at the application layer:
//   • Sliding window algorithm per bucket
//   • Per-IP rate limiting
//   • Per-token rate limiting (signing tokens)
//   • Per-phone rate limiting (SCA)
//   • Per-endpoint rate limiting
//   • Burst detection and progressive blocking
//   • Automatic cooldown with exponential backoff
//
// This runs INSIDE the application even though Cloudflare
// also rate-limits at the edge. Belt + suspenders.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

/** Rate limit bucket type */
export type BucketType = "ip" | "token" | "phone" | "endpoint" | "global";

/** Rate limit decision */
export interface RateLimitDecision {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Current request count in window */
  currentCount: number;
  /** Maximum allowed in window */
  limit: number;
  /** Window size in seconds */
  windowSeconds: number;
  /** Remaining requests in window */
  remaining: number;
  /** When the window resets (ISO timestamp) */
  resetsAt: string;
  /** Retry-After header value (seconds, 0 if allowed) */
  retryAfter: number;
  /** Bucket key */
  bucketKey: string;
  /** Bucket type */
  bucketType: BucketType;
}

/** Rate limit configuration for a bucket type */
export interface RateLimitConfig {
  /** Maximum requests per window */
  maxRequests: number;
  /** Window size in seconds */
  windowSeconds: number;
  /** Burst allowance (extra requests before hard block) */
  burstAllowance: number;
  /** Block duration in seconds (when limit exceeded) */
  blockDurationSeconds: number;
  /** Whether to apply exponential backoff on repeated violations */
  exponentialBackoff: boolean;
}

/** Sliding window entry */
interface WindowEntry {
  /** Request timestamps in current window */
  timestamps: number[];
  /** Number of violations */
  violations: number;
  /** Blocked until (epoch ms, 0 = not blocked) */
  blockedUntil: number;
  /** Current backoff multiplier */
  backoffMultiplier: number;
}

// ── Default Configurations ───────────────────────────────────

const DEFAULT_CONFIGS: Record<BucketType, RateLimitConfig> = {
  ip: {
    maxRequests: 60,
    windowSeconds: 60,
    burstAllowance: 10,
    blockDurationSeconds: 120,
    exponentialBackoff: true,
  },
  token: {
    maxRequests: 10,
    windowSeconds: 60,
    burstAllowance: 3,
    blockDurationSeconds: 300,
    exponentialBackoff: true,
  },
  phone: {
    maxRequests: 20,
    windowSeconds: 60,
    burstAllowance: 5,
    blockDurationSeconds: 180,
    exponentialBackoff: true,
  },
  endpoint: {
    maxRequests: 30,
    windowSeconds: 60,
    burstAllowance: 5,
    blockDurationSeconds: 60,
    exponentialBackoff: false,
  },
  global: {
    maxRequests: 200,
    windowSeconds: 60,
    burstAllowance: 50,
    blockDurationSeconds: 30,
    exponentialBackoff: false,
  },
};

/** Stricter limits for sensitive endpoints */
const SENSITIVE_ENDPOINT_CONFIGS: Record<string, RateLimitConfig> = {
  "/otp": {
    maxRequests: 5,
    windowSeconds: 300,
    burstAllowance: 0,
    blockDurationSeconds: 600,
    exponentialBackoff: true,
  },
  "/sign": {
    maxRequests: 10,
    windowSeconds: 60,
    burstAllowance: 2,
    blockDurationSeconds: 300,
    exponentialBackoff: true,
  },
  "/webhook": {
    maxRequests: 30,
    windowSeconds: 60,
    burstAllowance: 10,
    blockDurationSeconds: 300,
    exponentialBackoff: false,
  },
  "/view": {
    maxRequests: 20,
    windowSeconds: 60,
    burstAllowance: 5,
    blockDurationSeconds: 120,
    exponentialBackoff: true,
  },
};

// ── Rate Limiter ─────────────────────────────────────────────

export class RateLimiter {
  private buckets: Map<string, WindowEntry> = new Map();
  private configs: Map<BucketType, RateLimitConfig> = new Map();
  private endpointConfigs: Map<string, RateLimitConfig> = new Map();
  private totalChecks: number = 0;
  private totalBlocked: number = 0;

  constructor() {
    // Load defaults
    for (const [type, config] of Object.entries(DEFAULT_CONFIGS)) {
      this.configs.set(type as BucketType, { ...config });
    }
    for (const [path, config] of Object.entries(SENSITIVE_ENDPOINT_CONFIGS)) {
      this.endpointConfigs.set(path, { ...config });
    }

    // Periodic cleanup every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  // ── Primary Check ──────────────────────────────────────────

  /**
   * Check if a request should be rate-limited.
   */
  check(bucketType: BucketType, identifier: string, endpoint?: string): RateLimitDecision {
    this.totalChecks++;

    // Resolve config (use endpoint-specific if available)
    let config = this.configs.get(bucketType) || DEFAULT_CONFIGS[bucketType];
    if (endpoint && bucketType === "endpoint") {
      const epConfig = this.resolveEndpointConfig(endpoint);
      if (epConfig) config = epConfig;
    }

    const bucketKey = this.buildKey(bucketType, identifier, endpoint);
    const now = Date.now();
    const windowMs = config.windowSeconds * 1000;

    // Get or create window entry
    let entry = this.buckets.get(bucketKey);
    if (!entry) {
      entry = {
        timestamps: [],
        violations: 0,
        blockedUntil: 0,
        backoffMultiplier: 1,
      };
      this.buckets.set(bucketKey, entry);
    }

    // Check if currently blocked
    if (entry.blockedUntil > now) {
      this.totalBlocked++;
      const retryAfter = Math.ceil((entry.blockedUntil - now) / 1000);
      return {
        allowed: false,
        currentCount: entry.timestamps.length,
        limit: config.maxRequests,
        windowSeconds: config.windowSeconds,
        remaining: 0,
        resetsAt: new Date(entry.blockedUntil).toISOString(),
        retryAfter,
        bucketKey,
        bucketType,
      };
    }

    // Slide window — remove timestamps older than window
    const windowStart = now - windowMs;
    entry.timestamps = entry.timestamps.filter((t) => t > windowStart);

    // Check limit
    const effectiveLimit = config.maxRequests + config.burstAllowance;
    if (entry.timestamps.length >= effectiveLimit) {
      // Rate limit exceeded
      entry.violations++;
      this.totalBlocked++;

      // Calculate block duration with exponential backoff
      let blockMs = config.blockDurationSeconds * 1000;
      if (config.exponentialBackoff) {
        blockMs *= entry.backoffMultiplier;
        entry.backoffMultiplier = Math.min(entry.backoffMultiplier * 2, 32); // Cap at 32x
      }
      entry.blockedUntil = now + blockMs;

      return {
        allowed: false,
        currentCount: entry.timestamps.length,
        limit: config.maxRequests,
        windowSeconds: config.windowSeconds,
        remaining: 0,
        resetsAt: new Date(entry.blockedUntil).toISOString(),
        retryAfter: Math.ceil(blockMs / 1000),
        bucketKey,
        bucketType,
      };
    }

    // Allowed — record timestamp
    entry.timestamps.push(now);

    // Reset backoff if under normal limit
    if (entry.timestamps.length < config.maxRequests) {
      entry.backoffMultiplier = 1;
    }

    const remaining = Math.max(0, config.maxRequests - entry.timestamps.length);
    const oldestInWindow = entry.timestamps[0] || now;
    const resetsAt = new Date(oldestInWindow + windowMs).toISOString();

    return {
      allowed: true,
      currentCount: entry.timestamps.length,
      limit: config.maxRequests,
      windowSeconds: config.windowSeconds,
      remaining,
      resetsAt,
      retryAfter: 0,
      bucketKey,
      bucketType,
    };
  }

  /**
   * Convenience: check multiple buckets at once.
   * All must pass for request to be allowed.
   */
  checkMultiple(checks: Array<{ type: BucketType; identifier: string; endpoint?: string }>): {
    allowed: boolean;
    results: RateLimitDecision[];
    blockingBucket: string | null;
  } {
    const results: RateLimitDecision[] = [];
    let blockingBucket: string | null = null;

    for (const check of checks) {
      const result = this.check(check.type, check.identifier, check.endpoint);
      results.push(result);
      if (!result.allowed && !blockingBucket) {
        blockingBucket = result.bucketKey;
      }
    }

    return {
      allowed: results.every((r) => r.allowed),
      results,
      blockingBucket,
    };
  }

  // ── Configuration ──────────────────────────────────────────

  /**
   * Update rate limit configuration for a bucket type.
   */
  setConfig(bucketType: BucketType, config: Partial<RateLimitConfig>): void {
    const existing = this.configs.get(bucketType) || DEFAULT_CONFIGS[bucketType];
    this.configs.set(bucketType, { ...existing, ...config });
  }

  /**
   * Set endpoint-specific configuration.
   */
  setEndpointConfig(path: string, config: RateLimitConfig): void {
    this.endpointConfigs.set(path, config);
  }

  /**
   * Resolve endpoint config by matching path prefix.
   */
  private resolveEndpointConfig(endpoint: string): RateLimitConfig | null {
    // Exact match first
    if (this.endpointConfigs.has(endpoint)) {
      return this.endpointConfigs.get(endpoint)!;
    }

    // Prefix match
    for (const [prefix, config] of this.endpointConfigs) {
      if (endpoint.startsWith(prefix)) {
        return config;
      }
    }

    return null;
  }

  // ── Bucket Management ──────────────────────────────────────

  /**
   * Build a unique bucket key.
   */
  private buildKey(type: BucketType, identifier: string, endpoint?: string): string {
    if (endpoint) {
      return `${type}:${identifier}:${endpoint}`;
    }
    return `${type}:${identifier}`;
  }

  /**
   * Reset a specific bucket (e.g., after manual review).
   */
  resetBucket(bucketKey: string): boolean {
    return this.buckets.delete(bucketKey);
  }

  /**
   * Reset all buckets for an identifier across all types.
   */
  resetIdentifier(identifier: string): number {
    let count = 0;
    for (const key of this.buckets.keys()) {
      if (key.includes(`:${identifier}`)) {
        this.buckets.delete(key);
        count++;
      }
    }
    return count;
  }

  /**
   * Cleanup expired entries.
   */
  private cleanup(): void {
    const now = Date.now();
    const maxAge = 10 * 60 * 1000; // 10 minutes

    for (const [key, entry] of this.buckets) {
      // Remove if no recent activity and not blocked
      const lastActivity = entry.timestamps.length > 0
        ? entry.timestamps[entry.timestamps.length - 1]
        : 0;

      if (lastActivity < now - maxAge && entry.blockedUntil < now) {
        this.buckets.delete(key);
      }
    }
  }

  // ── Statistics ─────────────────────────────────────────────

  /**
   * Get rate limiter statistics.
   */
  getStats(): {
    totalChecks: number;
    totalBlocked: number;
    blockRate: string;
    activeBuckets: number;
    blockedBuckets: number;
    bucketsByType: Record<string, number>;
  } {
    const now = Date.now();
    let blockedBuckets = 0;
    const bucketsByType: Record<string, number> = {};

    for (const [key, entry] of this.buckets) {
      const type = key.split(":")[0];
      bucketsByType[type] = (bucketsByType[type] || 0) + 1;
      if (entry.blockedUntil > now) blockedBuckets++;
    }

    return {
      totalChecks: this.totalChecks,
      totalBlocked: this.totalBlocked,
      blockRate: this.totalChecks > 0
        ? ((this.totalBlocked / this.totalChecks) * 100).toFixed(2) + "%"
        : "0.00%",
      activeBuckets: this.buckets.size,
      blockedBuckets,
      bucketsByType,
    };
  }

  /**
   * Get all currently blocked buckets.
   */
  getBlockedBuckets(): Array<{ key: string; blockedUntil: string; violations: number }> {
    const now = Date.now();
    const blocked: Array<{ key: string; blockedUntil: string; violations: number }> = [];

    for (const [key, entry] of this.buckets) {
      if (entry.blockedUntil > now) {
        blocked.push({
          key,
          blockedUntil: new Date(entry.blockedUntil).toISOString(),
          violations: entry.violations,
        });
      }
    }

    return blocked;
  }

  /**
   * Format rate limiter status for CLI display.
   */
  formatStatus(): string {
    const stats = this.getStats();
    const blocked = this.getBlockedBuckets();

    const lines: string[] = [
      `  Application Rate Limiter`,
      `  ──────────────────────────────────────────────`,
      `  Total Checks: ${stats.totalChecks}`,
      `  Total Blocked: ${stats.totalBlocked}`,
      `  Block Rate: ${stats.blockRate}`,
      `  Active Buckets: ${stats.activeBuckets}`,
      `  Blocked Buckets: ${stats.blockedBuckets}`,
    ];

    if (Object.keys(stats.bucketsByType).length > 0) {
      lines.push(``);
      lines.push(`  Buckets by Type:`);
      for (const [type, count] of Object.entries(stats.bucketsByType)) {
        lines.push(`    ${type.padEnd(12)} ${count}`);
      }
    }

    if (blocked.length > 0) {
      lines.push(``);
      lines.push(`  Currently Blocked:`);
      for (const b of blocked) {
        lines.push(`    ${b.key.padEnd(40)} — ${b.violations} violations, until ${b.blockedUntil}`);
      }
    }

    return lines.join("\n");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: RateLimiter | null = null;
export function getRateLimiter(): RateLimiter {
  if (!_instance) _instance = new RateLimiter();
  return _instance;
}
