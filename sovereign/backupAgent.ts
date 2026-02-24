// ─────────────────────────────────────────────────────────────
// Sovereign Backup Agent — Automated Encrypted Ledger Backup
//
// Periodically snapshots ALL sovereign ledger data:
//   • accessLedger (SDC access events)
//   • conversationLedger (SCA telecom events)
//   • perimeterLedger (security events)
//   • signingSession store
//   • SDC intake, tokens, exports, fingerprints
//   • CID registry, event log, agreement states
//   • Key vault (already encrypted)
//   • Lifecycle registry, knowledge memory
//
// Architecture:
//   1. Collect all .doc-engine/*.json files
//   2. Bundle into single JSON manifest
//   3. Compute SHA-256 integrity hash
//   4. Encrypt with AES-256-GCM
//   5. Write to backups/ directory
//   6. Enforce retention policy (prune old snapshots)
//   7. Log to backup ledger (chain-hashed)
//
// This runs as a daemon process (--backup-daemon) or
// can be triggered on-demand (--backup-now).
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ── Types ────────────────────────────────────────────────────

export interface BackupManifest {
  /** Backup ID */
  backupId: string;
  /** ISO timestamp */
  timestamp: string;
  /** Engine version */
  engineVersion: string;
  /** Files included in this backup */
  files: BackupFileEntry[];
  /** Total size in bytes (uncompressed) */
  totalSizeBytes: number;
  /** SHA-256 hash of the combined payload */
  integrityHash: string;
  /** Whether backup was encrypted */
  encrypted: boolean;
  /** Machine hostname */
  hostname: string;
}

export interface BackupFileEntry {
  /** Relative path from .doc-engine */
  relativePath: string;
  /** File size in bytes */
  sizeBytes: number;
  /** SHA-256 hash of individual file */
  fileHash: string;
  /** Last modified time */
  lastModified: string;
}

export interface BackupResult {
  success: boolean;
  backupId: string;
  outputPath: string;
  manifest: BackupManifest;
  elapsedMs: number;
  error?: string;
}

export interface BackupLedgerEntry {
  /** Sequence number */
  sequence: number;
  /** Backup ID */
  backupId: string;
  /** ISO timestamp */
  timestamp: string;
  /** Event: created, pruned, restored, verified */
  event: "created" | "pruned" | "restored" | "verified" | "failed";
  /** Description */
  description: string;
  /** File count */
  fileCount: number;
  /** Total size */
  totalSizeBytes: number;
  /** Chain hash */
  chainHash: string;
}

export interface BackupLedgerStore {
  version: string;
  entries: BackupLedgerEntry[];
}

export interface RetentionResult {
  pruned: number;
  remaining: number;
  freedBytes: number;
}

// ── Constants ────────────────────────────────────────────────

const DATA_DIR = path.join(process.cwd(), ".doc-engine");
const BACKUP_DIR = path.join(process.cwd(), "backups");
const BACKUP_LEDGER_PATH = path.join(DATA_DIR, "backup-ledger.json");
const ENGINE_VERSION = "4.0.0";
const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

// AES-256-GCM parameters
const CIPHER_ALGO = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_ITERATIONS = 100000;

// ── Backup Agent ─────────────────────────────────────────────

export class BackupAgent {
  private ledger: BackupLedgerStore;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.ledger = this.loadLedger();
  }

  // ── Create Backup ──────────────────────────────────────────

  /**
   * Create a full backup of all sovereign data.
   */
  createBackup(encryptionKey?: string): BackupResult {
    const start = Date.now();
    const backupId = `BKP-${new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19)}-${crypto.randomBytes(4).toString("hex")}`;

    try {
      // Ensure backup directory exists
      if (!fs.existsSync(BACKUP_DIR)) {
        fs.mkdirSync(BACKUP_DIR, { recursive: true });
      }

      // Collect all ledger files
      const files = this.collectFiles();
      if (files.length === 0) {
        const result: BackupResult = {
          success: false,
          backupId,
          outputPath: "",
          manifest: this.buildManifest(backupId, [], 0, ""),
          elapsedMs: Date.now() - start,
          error: "No data files found in .doc-engine/",
        };
        this.recordEvent("failed", backupId, "No data files found", 0, 0);
        return result;
      }

      // Bundle all files into a single JSON payload
      const bundle: Record<string, string> = {};
      let totalSize = 0;
      for (const file of files) {
        const content = fs.readFileSync(file.absolutePath, "utf-8");
        bundle[file.relativePath] = content;
        totalSize += file.sizeBytes;
      }

      const payload = JSON.stringify(bundle, null, 2);
      const integrityHash = crypto.createHash("sha256").update(payload).digest("hex");

      // Build manifest
      const manifest = this.buildManifest(backupId, files, totalSize, integrityHash);
      const manifestJson = JSON.stringify(manifest, null, 2);

      let outputPath: string;

      if (encryptionKey) {
        // Encrypt payload + manifest together
        const combined = JSON.stringify({ manifest, payload: bundle });
        const encrypted = this.encrypt(combined, encryptionKey);
        outputPath = path.join(BACKUP_DIR, `${backupId}.enc`);
        fs.writeFileSync(outputPath, encrypted);
      } else {
        // Unencrypted — write manifest + payload
        outputPath = path.join(BACKUP_DIR, `${backupId}.json`);
        const output = JSON.stringify({ manifest, payload: bundle }, null, 2);
        fs.writeFileSync(outputPath, output, "utf-8");
      }

      this.recordEvent("created", backupId, `Backup created: ${files.length} files, ${this.formatBytes(totalSize)}`, files.length, totalSize);

      return {
        success: true,
        backupId,
        outputPath,
        manifest,
        elapsedMs: Date.now() - start,
      };
    } catch (err: any) {
      this.recordEvent("failed", backupId, `Backup failed: ${err.message}`, 0, 0);
      return {
        success: false,
        backupId,
        outputPath: "",
        manifest: this.buildManifest(backupId, [], 0, ""),
        elapsedMs: Date.now() - start,
        error: err.message,
      };
    }
  }

  // ── Verify Backup ──────────────────────────────────────────

  /**
   * Verify a backup file's integrity.
   */
  verifyBackup(backupPath: string, encryptionKey?: string): { valid: boolean; manifest: BackupManifest | null; details: string } {
    try {
      if (!fs.existsSync(backupPath)) {
        return { valid: false, manifest: null, details: `File not found: ${backupPath}` };
      }

      let parsed: { manifest: BackupManifest; payload: Record<string, string> };

      if (backupPath.endsWith(".enc")) {
        if (!encryptionKey) {
          return { valid: false, manifest: null, details: "Encrypted backup requires decryption key" };
        }
        const raw = fs.readFileSync(backupPath);
        const decrypted = this.decrypt(raw, encryptionKey);
        parsed = JSON.parse(decrypted);
      } else {
        const raw = fs.readFileSync(backupPath, "utf-8");
        parsed = JSON.parse(raw);
      }

      const { manifest, payload } = parsed;

      // Verify integrity hash
      const payloadStr = JSON.stringify(payload, null, 2);
      const computedHash = crypto.createHash("sha256").update(payloadStr).digest("hex");

      if (computedHash !== manifest.integrityHash) {
        this.recordEvent("verified", manifest.backupId, "INTEGRITY MISMATCH", manifest.files.length, manifest.totalSizeBytes);
        return {
          valid: false,
          manifest,
          details: `Integrity hash mismatch. Expected: ${manifest.integrityHash.substring(0, 16)}..., got: ${computedHash.substring(0, 16)}...`,
        };
      }

      // Verify individual file hashes
      for (const fileEntry of manifest.files) {
        const content = payload[fileEntry.relativePath];
        if (!content) {
          return { valid: false, manifest, details: `Missing file in payload: ${fileEntry.relativePath}` };
        }
        const fileHash = crypto.createHash("sha256").update(content).digest("hex");
        if (fileHash !== fileEntry.fileHash) {
          return { valid: false, manifest, details: `Hash mismatch for ${fileEntry.relativePath}` };
        }
      }

      this.recordEvent("verified", manifest.backupId, `Verified: ${manifest.files.length} files intact`, manifest.files.length, manifest.totalSizeBytes);
      return { valid: true, manifest, details: `All ${manifest.files.length} files verified. Integrity hash matches.` };
    } catch (err: any) {
      return { valid: false, manifest: null, details: `Verification error: ${err.message}` };
    }
  }

  // ── Restore Backup ─────────────────────────────────────────

  /**
   * Restore ledger data from a backup file.
   * WARNING: This overwrites current .doc-engine data!
   */
  restoreBackup(backupPath: string, encryptionKey?: string): { success: boolean; filesRestored: number; details: string } {
    try {
      // First verify
      const verification = this.verifyBackup(backupPath, encryptionKey);
      if (!verification.valid) {
        return { success: false, filesRestored: 0, details: `Cannot restore — verification failed: ${verification.details}` };
      }

      // Read and parse
      let parsed: { manifest: BackupManifest; payload: Record<string, string> };
      if (backupPath.endsWith(".enc")) {
        const raw = fs.readFileSync(backupPath);
        const decrypted = this.decrypt(raw, encryptionKey!);
        parsed = JSON.parse(decrypted);
      } else {
        const raw = fs.readFileSync(backupPath, "utf-8");
        parsed = JSON.parse(raw);
      }

      const { manifest, payload } = parsed;

      // Ensure data directory exists
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }

      // Restore each file
      let restored = 0;
      for (const [relativePath, content] of Object.entries(payload)) {
        const targetPath = path.join(DATA_DIR, relativePath);
        const targetDir = path.dirname(targetPath);
        if (!fs.existsSync(targetDir)) {
          fs.mkdirSync(targetDir, { recursive: true });
        }
        fs.writeFileSync(targetPath, content, "utf-8");
        restored++;
      }

      this.recordEvent("restored", manifest.backupId, `Restored ${restored} files from backup`, restored, manifest.totalSizeBytes);
      return { success: true, filesRestored: restored, details: `Restored ${restored} files from backup ${manifest.backupId}` };
    } catch (err: any) {
      return { success: false, filesRestored: 0, details: `Restore error: ${err.message}` };
    }
  }

  // ── Retention Policy ───────────────────────────────────────

  /**
   * Prune backups older than retention period.
   */
  enforceRetention(retentionDays: number = 30): RetentionResult {
    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

    if (!fs.existsSync(BACKUP_DIR)) {
      return { pruned: 0, remaining: 0, freedBytes: 0 };
    }

    const files = fs.readdirSync(BACKUP_DIR).filter((f) => f.startsWith("BKP-"));
    let pruned = 0;
    let freedBytes = 0;

    for (const file of files) {
      const filePath = path.join(BACKUP_DIR, file);
      const stat = fs.statSync(filePath);
      if (stat.mtimeMs < cutoff) {
        freedBytes += stat.size;
        fs.unlinkSync(filePath);
        pruned++;
      }
    }

    if (pruned > 0) {
      this.recordEvent("pruned", `retention-${Date.now()}`, `Pruned ${pruned} backups older than ${retentionDays} days. Freed ${this.formatBytes(freedBytes)}`, pruned, freedBytes);
    }

    const remaining = fs.readdirSync(BACKUP_DIR).filter((f) => f.startsWith("BKP-")).length;
    return { pruned, remaining, freedBytes };
  }

  // ── Daemon Mode ────────────────────────────────────────────

  /**
   * Start the backup daemon — runs periodically.
   */
  startDaemon(intervalMinutes: number = 15, encryptionKey?: string, retentionDays: number = 30): void {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN BACKUP AGENT — DAEMON MODE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    console.log(`  Interval: every ${intervalMinutes} minutes`);
    console.log(`  Encryption: ${encryptionKey ? "AES-256-GCM" : "DISABLED (⚠ not recommended)"}`);
    console.log(`  Retention: ${retentionDays} days`);
    console.log(`  Backup dir: ${BACKUP_DIR}`);
    console.log(`  Data dir: ${DATA_DIR}`);
    console.log("");

    // Initial backup on start
    console.log("  Running initial backup...");
    const initial = this.createBackup(encryptionKey);
    if (initial.success) {
      console.log(`  ✅ Initial backup: ${initial.backupId} (${initial.manifest.files.length} files, ${initial.elapsedMs}ms)`);
    } else {
      console.log(`  ⚠ Initial backup failed: ${initial.error}`);
    }

    // Schedule recurring backups
    const intervalMs = intervalMinutes * 60 * 1000;
    this.intervalHandle = setInterval(() => {
      const result = this.createBackup(encryptionKey);
      const now = new Date().toISOString().substring(0, 19);
      if (result.success) {
        console.log(`  [${now}] Backup: ${result.backupId} — ${result.manifest.files.length} files (${result.elapsedMs}ms)`);
      } else {
        console.log(`  [${now}] Backup FAILED: ${result.error}`);
      }

      // Enforce retention
      const retention = this.enforceRetention(retentionDays);
      if (retention.pruned > 0) {
        console.log(`  [${now}] Pruned ${retention.pruned} old backups (freed ${this.formatBytes(retention.freedBytes)})`);
      }
    }, intervalMs);

    console.log(`  Daemon started. Next backup in ${intervalMinutes} minutes.`);
    console.log("");
  }

  /**
   * Stop the daemon.
   */
  stopDaemon(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
  }

  // ── List Backups ───────────────────────────────────────────

  /**
   * List all available backups.
   */
  listBackups(): Array<{ filename: string; sizeBytes: number; created: string; encrypted: boolean }> {
    if (!fs.existsSync(BACKUP_DIR)) return [];

    return fs
      .readdirSync(BACKUP_DIR)
      .filter((f) => f.startsWith("BKP-"))
      .map((f) => {
        const filePath = path.join(BACKUP_DIR, f);
        const stat = fs.statSync(filePath);
        return {
          filename: f,
          sizeBytes: stat.size,
          created: stat.mtime.toISOString(),
          encrypted: f.endsWith(".enc"),
        };
      })
      .sort((a, b) => b.created.localeCompare(a.created));
  }

  // ── Display ────────────────────────────────────────────────

  /**
   * Format backup status for CLI display.
   */
  formatStatus(): string {
    const backups = this.listBackups();
    const chain = this.verifyLedgerChain();

    const lines: string[] = [
      `  Sovereign Backup Agent`,
      `  ──────────────────────────────────────────────`,
      `  Total Backups: ${backups.length}`,
      `  Backup Directory: ${BACKUP_DIR}`,
      `  Ledger Chain: ${chain.intact ? "✓ INTACT" : "✗ BROKEN"}`,
      `  Ledger Entries: ${this.ledger.entries.length}`,
    ];

    if (backups.length > 0) {
      const totalSize = backups.reduce((sum, b) => sum + b.sizeBytes, 0);
      lines.push(`  Total Size: ${this.formatBytes(totalSize)}`);
      lines.push(`  Latest: ${backups[0].filename} (${backups[0].created.substring(0, 19)})`);
      lines.push(`  Oldest: ${backups[backups.length - 1].filename} (${backups[backups.length - 1].created.substring(0, 19)})`);
      lines.push(``);
      lines.push(`  Recent Backups:`);
      for (const b of backups.slice(0, 5)) {
        const enc = b.encrypted ? "🔐" : "📄";
        lines.push(`    ${enc} ${b.filename} — ${this.formatBytes(b.sizeBytes)} — ${b.created.substring(0, 19)}`);
      }
    } else {
      lines.push(`  No backups found.`);
    }

    return lines.join("\n");
  }

  // ── File Collection ────────────────────────────────────────

  private collectFiles(): Array<{ absolutePath: string; relativePath: string; sizeBytes: number; lastModified: string; hash: string }> {
    if (!fs.existsSync(DATA_DIR)) return [];

    const results: Array<{ absolutePath: string; relativePath: string; sizeBytes: number; lastModified: string; hash: string }> = [];
    this.walkDir(DATA_DIR, DATA_DIR, results);
    return results;
  }

  private walkDir(
    dir: string,
    root: string,
    results: Array<{ absolutePath: string; relativePath: string; sizeBytes: number; lastModified: string; hash: string }>
  ): void {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        this.walkDir(fullPath, root, results);
      } else if (entry.isFile() && (entry.name.endsWith(".json") || entry.name.endsWith(".txt"))) {
        const stat = fs.statSync(fullPath);
        const content = fs.readFileSync(fullPath, "utf-8");
        const hash = crypto.createHash("sha256").update(content).digest("hex");
        results.push({
          absolutePath: fullPath,
          relativePath: path.relative(root, fullPath),
          sizeBytes: stat.size,
          lastModified: stat.mtime.toISOString(),
          hash,
        });
      }
    }
  }

  // ── Encryption ─────────────────────────────────────────────

  private encrypt(plaintext: string, passphrase: string): Buffer {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = crypto.pbkdf2Sync(passphrase, salt, KEY_ITERATIONS, 32, "sha512");
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(CIPHER_ALGO, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Format: salt(32) + iv(16) + authTag(16) + ciphertext
    return Buffer.concat([salt, iv, authTag, encrypted]);
  }

  private decrypt(data: Buffer, passphrase: string): string {
    const salt = data.subarray(0, SALT_LENGTH);
    const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const authTag = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = data.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

    const key = crypto.pbkdf2Sync(passphrase, salt, KEY_ITERATIONS, 32, "sha512");

    const decipher = crypto.createDecipheriv(CIPHER_ALGO, key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf-8");
  }

  // ── Manifest ───────────────────────────────────────────────

  private buildManifest(
    backupId: string,
    files: Array<{ relativePath: string; sizeBytes: number; lastModified: string; hash: string }>,
    totalSize: number,
    integrityHash: string
  ): BackupManifest {
    return {
      backupId,
      timestamp: new Date().toISOString(),
      engineVersion: ENGINE_VERSION,
      files: files.map((f) => ({
        relativePath: f.relativePath,
        sizeBytes: f.sizeBytes,
        fileHash: f.hash,
        lastModified: f.lastModified,
      })),
      totalSizeBytes: totalSize,
      integrityHash,
      encrypted: false, // Caller updates if encrypting
      hostname: require("os").hostname(),
    };
  }

  // ── Backup Ledger ──────────────────────────────────────────

  private recordEvent(event: BackupLedgerEntry["event"], backupId: string, description: string, fileCount: number, totalSize: number): void {
    const sequence = this.ledger.entries.length + 1;
    const previousHash = this.ledger.entries.length > 0
      ? this.ledger.entries[this.ledger.entries.length - 1].chainHash
      : GENESIS_HASH;

    const data = `${sequence}|${backupId}|${event}|${new Date().toISOString()}|${previousHash}`;
    const chainHash = crypto.createHash("sha256").update(data).digest("hex");

    this.ledger.entries.push({
      sequence,
      backupId,
      timestamp: new Date().toISOString(),
      event,
      description,
      fileCount,
      totalSizeBytes: totalSize,
      chainHash,
    });

    this.persistLedger();
  }

  private verifyLedgerChain(): { intact: boolean; brokenAt?: number } {
    let previousHash = GENESIS_HASH;
    for (let i = 0; i < this.ledger.entries.length; i++) {
      const entry = this.ledger.entries[i];
      const data = `${entry.sequence}|${entry.backupId}|${entry.event}|${entry.timestamp}|${previousHash}`;
      const expectedHash = crypto.createHash("sha256").update(data).digest("hex");
      if (expectedHash !== entry.chainHash) {
        return { intact: false, brokenAt: i + 1 };
      }
      previousHash = entry.chainHash;
    }
    return { intact: true };
  }

  private loadLedger(): BackupLedgerStore {
    try {
      if (fs.existsSync(BACKUP_LEDGER_PATH)) {
        return JSON.parse(fs.readFileSync(BACKUP_LEDGER_PATH, "utf-8"));
      }
    } catch { /* fresh start */ }
    return { version: "1.0.0", entries: [] };
  }

  private persistLedger(): void {
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(BACKUP_LEDGER_PATH, JSON.stringify(this.ledger, null, 2), "utf-8");
    } catch (err) {
      console.error("[Backup Agent] Failed to persist ledger:", err);
    }
  }

  // ── Utils ──────────────────────────────────────────────────

  private formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)}MB`;
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: BackupAgent | null = null;
export function getBackupAgent(): BackupAgent {
  if (!_instance) _instance = new BackupAgent();
  return _instance;
}
