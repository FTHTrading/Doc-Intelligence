// ─────────────────────────────────────────────────────────────
// Encrypted IPFS — Client-Side Encryption Before IPFS Push
//
// Flow:
//   Document → AES-256-GCM Encrypt → IPFS Add → Store CID
//   Encryption key stored separately (never on IPFS)
//
// CID is public. Content is unreadable without key.
//
// Key derivation options:
//   1. Random key (stored in vault file)
//   2. Passphrase-derived (PBKDF2)
//   3. Signer-key-derived (from signature hash)
//
// This creates a private, distributed, sovereign archive.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";

// ── Types ────────────────────────────────────────────────────

/** Encryption algorithm used */
export type EncryptionAlgorithm = "aes-256-gcm";

/** Key derivation method */
export type KeyDerivation = "random" | "passphrase" | "signer-key";

/** Encrypted payload metadata */
export interface EncryptedPayload {
  /** The encrypted data (base64 encoded) */
  ciphertext: string;
  /** Initialization vector (base64) */
  iv: string;
  /** Authentication tag (base64, GCM mode) */
  authTag: string;
  /** Encryption algorithm */
  algorithm: EncryptionAlgorithm;
  /** Key derivation method used */
  keyDerivation: KeyDerivation;
  /** Salt for passphrase derivation (base64, only if passphrase-derived) */
  salt?: string;
  /** SHA-256 hash of the plaintext (for verification after decryption) */
  plaintextHash: string;
  /** Size of plaintext in bytes */
  plaintextSize: number;
  /** ISO timestamp of encryption */
  encryptedAt: string;
}

/** Key vault entry — stored separately from encrypted content */
export interface KeyVaultEntry {
  /** Document ID this key belongs to */
  documentId: string;
  /** Document SKU */
  sku: string;
  /** The encryption key (hex) — THIS IS SENSITIVE */
  key: string;
  /** Key derivation method */
  derivation: KeyDerivation;
  /** CID of the encrypted content on IPFS */
  encryptedCID?: string;
  /** SHA-256 hash of the plaintext */
  plaintextHash: string;
  /** Created timestamp */
  createdAt: string;
}

/** Encryption result */
export interface EncryptionResult {
  /** Encrypted payload (safe to push to IPFS) */
  payload: EncryptedPayload;
  /** Encryption key (MUST be stored securely, never on IPFS) */
  key: string;
  /** Key as Buffer */
  keyBuffer: Buffer;
}

/** Decryption result */
export interface DecryptionResult {
  /** Decrypted plaintext */
  plaintext: Buffer;
  /** Verified: plaintext hash matches */
  verified: boolean;
}

/** IPFS push result with encryption metadata */
export interface EncryptedIPFSResult {
  /** CID on IPFS */
  cid: string;
  /** Size on IPFS */
  size: number;
  /** Document ID */
  documentId: string;
  /** Encryption key (hex) — DO NOT EXPOSE */
  encryptionKey: string;
  /** Plaintext hash */
  plaintextHash: string;
  /** Gateway URL */
  gatewayUrl?: string;
}

// ── Encryption Engine ────────────────────────────────────────

const ALGORITHM: EncryptionAlgorithm = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16;  // 128 bits
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;

/**
 * Encrypt a buffer using AES-256-GCM with a random key.
 */
export function encryptBuffer(plaintext: Buffer): EncryptionResult {
  const key = crypto.randomBytes(KEY_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const plaintextHash = crypto.createHash("sha256").update(plaintext).digest("hex");

  return {
    payload: {
      ciphertext: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      algorithm: ALGORITHM,
      keyDerivation: "random",
      plaintextHash,
      plaintextSize: plaintext.length,
      encryptedAt: new Date().toISOString(),
    },
    key: key.toString("hex"),
    keyBuffer: key,
  };
}

/**
 * Encrypt a buffer using a passphrase (PBKDF2 key derivation).
 */
export function encryptWithPassphrase(plaintext: Buffer, passphrase: string): EncryptionResult {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const plaintextHash = crypto.createHash("sha256").update(plaintext).digest("hex");

  return {
    payload: {
      ciphertext: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      algorithm: ALGORITHM,
      keyDerivation: "passphrase",
      salt: salt.toString("base64"),
      plaintextHash,
      plaintextSize: plaintext.length,
      encryptedAt: new Date().toISOString(),
    },
    key: key.toString("hex"),
    keyBuffer: key,
  };
}

/**
 * Encrypt a buffer using a signer key (derived from signature hash).
 */
export function encryptWithSignerKey(plaintext: Buffer, signatureHash: string): EncryptionResult {
  // Derive a 256-bit key from the signature hash using SHA-512 truncation
  const derived = crypto.createHash("sha512").update(signatureHash).digest();
  const key = derived.subarray(0, KEY_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const plaintextHash = crypto.createHash("sha256").update(plaintext).digest("hex");

  return {
    payload: {
      ciphertext: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      algorithm: ALGORITHM,
      keyDerivation: "signer-key",
      plaintextHash,
      plaintextSize: plaintext.length,
      encryptedAt: new Date().toISOString(),
    },
    key: key.toString("hex"),
    keyBuffer: key,
  };
}

/**
 * Decrypt an encrypted payload.
 */
export function decryptPayload(payload: EncryptedPayload, key: string): DecryptionResult {
  const keyBuffer = Buffer.from(key, "hex");
  const iv = Buffer.from(payload.iv, "base64");
  const authTag = Buffer.from(payload.authTag, "base64");
  const ciphertext = Buffer.from(payload.ciphertext, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuffer, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  const hash = crypto.createHash("sha256").update(decrypted).digest("hex");
  const verified = hash === payload.plaintextHash;

  return { plaintext: decrypted, verified };
}

/**
 * Encrypt a file and return the encrypted payload.
 */
export function encryptFile(
  filePath: string,
  options?: { passphrase?: string; signerKey?: string }
): EncryptionResult {
  const plaintext = fs.readFileSync(filePath);

  if (options?.passphrase) {
    return encryptWithPassphrase(plaintext, options.passphrase);
  }
  if (options?.signerKey) {
    return encryptWithSignerKey(plaintext, options.signerKey);
  }
  return encryptBuffer(plaintext);
}

// ── Key Vault ────────────────────────────────────────────────

const VAULT_FILE = "key-vault.json";

interface VaultStore {
  engine: string;
  version: string;
  warning: string;
  entries: KeyVaultEntry[];
}

/**
 * Persistent key vault for encryption keys.
 * Keys are stored locally — never pushed to IPFS or any remote store.
 */
export class KeyVault {
  private store: VaultStore;
  private vaultPath: string;

  constructor(vaultDir: string = ".doc-engine") {
    if (!fs.existsSync(vaultDir)) {
      fs.mkdirSync(vaultDir, { recursive: true });
    }
    this.vaultPath = path.join(vaultDir, VAULT_FILE);
    this.store = this.load();
  }

  /**
   * Store an encryption key.
   */
  storeKey(entry: KeyVaultEntry): void {
    // Check for duplicate
    const existing = this.store.entries.findIndex(
      (e) => e.documentId === entry.documentId
    );
    if (existing >= 0) {
      this.store.entries[existing] = entry; // update
    } else {
      this.store.entries.push(entry);
    }
    this.save();
  }

  /**
   * Retrieve a key by document ID.
   */
  getKey(documentId: string): KeyVaultEntry | undefined {
    return this.store.entries.find((e) => e.documentId === documentId);
  }

  /**
   * Retrieve a key by SKU.
   */
  getKeyBySKU(sku: string): KeyVaultEntry | undefined {
    return this.store.entries.find((e) => e.sku === sku);
  }

  /**
   * Retrieve a key by CID (for decryption from IPFS).
   */
  getKeyByCID(cid: string): KeyVaultEntry | undefined {
    return this.store.entries.find((e) => e.encryptedCID === cid);
  }

  /**
   * List all vault entries (keys are masked).
   */
  listEntries(): Array<Omit<KeyVaultEntry, "key"> & { keyPreview: string }> {
    return this.store.entries.map((e) => ({
      documentId: e.documentId,
      sku: e.sku,
      derivation: e.derivation,
      encryptedCID: e.encryptedCID,
      plaintextHash: e.plaintextHash,
      createdAt: e.createdAt,
      keyPreview: e.key.substring(0, 8) + "..." + e.key.substring(e.key.length - 8),
    }));
  }

  /**
   * Get vault statistics.
   */
  getStats(): { totalKeys: number; byDerivation: Record<string, number> } {
    const byDerivation: Record<string, number> = {};
    for (const e of this.store.entries) {
      byDerivation[e.derivation] = (byDerivation[e.derivation] || 0) + 1;
    }
    return { totalKeys: this.store.entries.length, byDerivation };
  }

  private load(): VaultStore {
    if (fs.existsSync(this.vaultPath)) {
      try {
        const raw = fs.readFileSync(this.vaultPath, "utf-8");
        return JSON.parse(raw) as VaultStore;
      } catch {
        console.warn("[VAULT] Corrupt vault file — creating new one");
      }
    }
    return {
      engine: "Document Intelligence Engine",
      version: "4.0.0",
      warning: "THIS FILE CONTAINS ENCRYPTION KEYS. PROTECT IT ACCORDINGLY.",
      entries: [],
    };
  }

  private save(): void {
    fs.writeFileSync(this.vaultPath, JSON.stringify(this.store, null, 2), "utf-8");
  }
}

// ── Singleton ────────────────────────────────────────────────

let _vault: KeyVault | null = null;

export function getKeyVault(vaultDir?: string): KeyVault {
  if (!_vault) {
    _vault = new KeyVault(vaultDir || ".doc-engine");
  }
  return _vault;
}
