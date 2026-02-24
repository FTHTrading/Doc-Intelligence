// ─────────────────────────────────────────────────────────────
// Key Management Abstraction Layer — KeyProvider Interface
//
// Decouples ALL cryptographic key operations from the pipeline.
// The engine never touches raw keys directly — it asks a
// KeyProvider to perform the operation.
//
// Adapters:
//   • LocalVaultAdapter  — wraps existing KeyVault (dev/local)
//   • HSMAdapter         — interface-ready for HSM integration
//   • (Future) FireblocksAdapter, LedgerAdapter, MPCAdapter
//
// This is the architectural firewall between "math" and "policy."
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";

// ── Core Types ───────────────────────────────────────────────

/** Key derivation method */
export type KeyDerivation =
  | "random"           // Secure random (crypto.randomBytes)
  | "passphrase"       // PBKDF2 from user passphrase
  | "signer-key"       // Derived from signer identity hash
  | "hsm-managed"      // Key never leaves HSM boundary
  | "mpc-shared"       // Multi-party computation shares
  | "external";        // Key managed externally (Fireblocks, Ledger, etc.)

/** Key purpose classification */
export type KeyPurpose =
  | "encryption"       // AES-256 document encryption
  | "signing"          // Digital signature generation
  | "anchoring"        // Ledger anchor authentication
  | "identity"         // Signer identity derivation
  | "transport";       // Session/transport-layer encryption

/** Key metadata — what the engine knows about a key without the key itself */
export interface KeyMetadata {
  /** Unique key identifier */
  keyId: string;
  /** How the key was derived */
  derivation: KeyDerivation;
  /** What the key is used for */
  purpose: KeyPurpose;
  /** Associated document ID */
  documentId?: string;
  /** Associated document SKU */
  sku?: string;
  /** Key creation timestamp */
  createdAt: string;
  /** Whether the key material is accessible (vs. HSM-sealed) */
  extractable: boolean;
  /** Provider that manages this key */
  provider: string;
  /** Algorithm used */
  algorithm: string;
  /** Key length in bits */
  keyLengthBits: number;
}

/** Encryption result from a KeyProvider */
export interface KeyProviderEncryptResult {
  /** Encrypted ciphertext (base64) */
  ciphertext: string;
  /** Initialization vector (hex) */
  iv: string;
  /** Authentication tag (hex) — for GCM modes */
  authTag: string;
  /** Algorithm used */
  algorithm: string;
  /** Key ID used for encryption */
  keyId: string;
  /** SHA-256 of the plaintext (for integrity verification) */
  plaintextHash: string;
  /** Size of the plaintext in bytes */
  plaintextSize: number;
}

/** Decryption result from a KeyProvider */
export interface KeyProviderDecryptResult {
  /** Decrypted plaintext buffer */
  plaintext: Buffer;
  /** SHA-256 of the decrypted data (for integrity check) */
  hash: string;
  /** Whether integrity check passed */
  verified: boolean;
}

/** Signing result from a KeyProvider */
export interface KeyProviderSignResult {
  /** The signature (hex) */
  signature: string;
  /** Algorithm used for signing (e.g., 'sha256') */
  algorithm: string;
  /** Key ID used for signing */
  keyId: string;
  /** Timestamp of signing operation */
  signedAt: string;
}

// ── KeyProvider Interface ────────────────────────────────────

/**
 * Abstract key management interface.
 * 
 * ALL cryptographic operations in the engine go through this.
 * Implementations control where keys live and how operations execute.
 * The engine NEVER sees raw key material when using HSM/external providers.
 */
export interface KeyProvider {
  /** Provider name identifier */
  readonly name: string;

  /** Whether this provider supports key extraction */
  readonly extractable: boolean;

  /**
   * Generate or derive a new key for a document.
   * Returns metadata (never raw key material for non-extractable providers).
   */
  generateKey(params: {
    purpose: KeyPurpose;
    derivation: KeyDerivation;
    documentId?: string;
    sku?: string;
    passphrase?: string;
    signerHash?: string;
  }): Promise<KeyMetadata>;

  /**
   * Encrypt data using a key identified by keyId.
   * The provider handles key lookup and encryption internally.
   */
  encrypt(keyId: string, plaintext: Buffer): Promise<KeyProviderEncryptResult>;

  /**
   * Decrypt data using a key identified by keyId.
   * The provider handles key lookup and decryption internally.
   */
  decrypt(keyId: string, params: {
    ciphertext: string;
    iv: string;
    authTag: string;
    expectedHash?: string;
  }): Promise<KeyProviderDecryptResult>;

  /**
   * Sign a hash using a key identified by keyId.
   * For SHA-256 HMAC signing (document integrity, not public-key signing).
   */
  sign(keyId: string, hash: string): Promise<KeyProviderSignResult>;

  /**
   * Verify a signature against a hash.
   */
  verify(keyId: string, hash: string, signature: string): Promise<boolean>;

  /**
   * Get metadata for a stored key.
   */
  getKeyMetadata(keyId: string): Promise<KeyMetadata | undefined>;

  /**
   * List all keys managed by this provider.
   */
  listKeys(filter?: { documentId?: string; purpose?: KeyPurpose }): Promise<KeyMetadata[]>;

  /**
   * Rotate a key (generate new, mark old as superseded).
   * Returns metadata for the new key.
   */
  rotateKey(oldKeyId: string): Promise<KeyMetadata>;

  /**
   * Destroy a key (secure deletion).
   * Once destroyed, the key cannot be recovered.
   */
  destroyKey(keyId: string): Promise<boolean>;

  /**
   * Export provider statistics.
   */
  getStats(): Promise<{
    totalKeys: number;
    byPurpose: Record<string, number>;
    byDerivation: Record<string, number>;
    provider: string;
  }>;
}

// ── LocalVaultAdapter ────────────────────────────────────────

/**
 * Local file-based key vault. Wraps the existing KeyVault
 * pattern but conforms to the KeyProvider interface.
 *
 * Keys are stored as hex in a JSON file.
 * Suitable for development and single-operator deployments.
 * NOT suitable for multi-party or high-security environments.
 */

interface LocalKeyEntry {
  keyId: string;
  key: string;        // hex-encoded key material
  metadata: KeyMetadata;
  supersededBy?: string;
  destroyedAt?: string;
}

interface LocalVaultStore {
  engine: string;
  version: string;
  warning: string;
  entries: LocalKeyEntry[];
}

const LOCAL_VAULT_FILE = "sovereign-key-vault.json";

export class LocalVaultAdapter implements KeyProvider {
  readonly name = "local-vault";
  readonly extractable = true;

  private store: LocalVaultStore;
  private storePath: string;

  constructor(storeDir: string = ".doc-engine") {
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.storePath = path.join(storeDir, LOCAL_VAULT_FILE);
    this.store = this.load();
  }

  async generateKey(params: {
    purpose: KeyPurpose;
    derivation: KeyDerivation;
    documentId?: string;
    sku?: string;
    passphrase?: string;
    signerHash?: string;
  }): Promise<KeyMetadata> {
    const keyId = crypto.randomBytes(16).toString("hex");
    let key: string;

    switch (params.derivation) {
      case "passphrase": {
        if (!params.passphrase) throw new Error("[KEYVAULT] Passphrase required for passphrase derivation");
        const salt = crypto.randomBytes(32);
        key = crypto.pbkdf2Sync(params.passphrase, salt, 100000, 32, "sha512").toString("hex");
        break;
      }
      case "signer-key": {
        if (!params.signerHash) throw new Error("[KEYVAULT] Signer hash required for signer-key derivation");
        key = crypto.createHash("sha512").update(params.signerHash).digest("hex").substring(0, 64);
        break;
      }
      case "random":
      default: {
        key = crypto.randomBytes(32).toString("hex");
        break;
      }
    }

    const metadata: KeyMetadata = {
      keyId,
      derivation: params.derivation,
      purpose: params.purpose,
      documentId: params.documentId,
      sku: params.sku,
      createdAt: new Date().toISOString(),
      extractable: true,
      provider: this.name,
      algorithm: "aes-256-gcm",
      keyLengthBits: 256,
    };

    const entry: LocalKeyEntry = { keyId, key, metadata };
    this.store.entries.push(entry);
    this.save();

    return metadata;
  }

  async encrypt(keyId: string, plaintext: Buffer): Promise<KeyProviderEncryptResult> {
    const entry = this.findKey(keyId);
    if (!entry) throw new Error(`[KEYVAULT] Key not found: ${keyId}`);

    const keyBuffer = Buffer.from(entry.key, "hex");
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", keyBuffer, iv);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const plaintextHash = crypto.createHash("sha256").update(plaintext).digest("hex");

    return {
      ciphertext: encrypted.toString("base64"),
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      algorithm: "aes-256-gcm",
      keyId,
      plaintextHash,
      plaintextSize: plaintext.length,
    };
  }

  async decrypt(keyId: string, params: {
    ciphertext: string;
    iv: string;
    authTag: string;
    expectedHash?: string;
  }): Promise<KeyProviderDecryptResult> {
    const entry = this.findKey(keyId);
    if (!entry) throw new Error(`[KEYVAULT] Key not found: ${keyId}`);

    const keyBuffer = Buffer.from(entry.key, "hex");
    const iv = Buffer.from(params.iv, "hex");
    const authTag = Buffer.from(params.authTag, "hex");
    const ciphertext = Buffer.from(params.ciphertext, "base64");

    const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuffer, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const hash = crypto.createHash("sha256").update(decrypted).digest("hex");

    let verified = true;
    if (params.expectedHash) {
      verified = hash === params.expectedHash;
    }

    return { plaintext: decrypted, hash, verified };
  }

  async sign(keyId: string, hash: string): Promise<KeyProviderSignResult> {
    const entry = this.findKey(keyId);
    if (!entry) throw new Error(`[KEYVAULT] Key not found: ${keyId}`);

    const signature = crypto
      .createHmac("sha256", Buffer.from(entry.key, "hex"))
      .update(hash)
      .digest("hex");

    return {
      signature,
      algorithm: "hmac-sha256",
      keyId,
      signedAt: new Date().toISOString(),
    };
  }

  async verify(keyId: string, hash: string, signature: string): Promise<boolean> {
    const result = await this.sign(keyId, hash);
    return result.signature === signature;
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata | undefined> {
    const entry = this.findKey(keyId);
    return entry?.metadata;
  }

  async listKeys(filter?: { documentId?: string; purpose?: KeyPurpose }): Promise<KeyMetadata[]> {
    let entries = this.store.entries.filter(e => !e.destroyedAt);
    if (filter?.documentId) {
      entries = entries.filter(e => e.metadata.documentId === filter.documentId);
    }
    if (filter?.purpose) {
      entries = entries.filter(e => e.metadata.purpose === filter.purpose);
    }
    return entries.map(e => e.metadata);
  }

  async rotateKey(oldKeyId: string): Promise<KeyMetadata> {
    const oldEntry = this.findKey(oldKeyId);
    if (!oldEntry) throw new Error(`[KEYVAULT] Key not found for rotation: ${oldKeyId}`);

    // Generate new key with same params
    const newMeta = await this.generateKey({
      purpose: oldEntry.metadata.purpose,
      derivation: "random", // Rotated keys always use random derivation
      documentId: oldEntry.metadata.documentId,
      sku: oldEntry.metadata.sku,
    });

    // Mark old key as superseded
    oldEntry.supersededBy = newMeta.keyId;
    this.save();

    console.log(`[KEYVAULT] Key rotated: ${oldKeyId.substring(0, 8)}... → ${newMeta.keyId.substring(0, 8)}...`);
    return newMeta;
  }

  async destroyKey(keyId: string): Promise<boolean> {
    const entry = this.findKey(keyId);
    if (!entry) return false;

    // Overwrite key material with zeros then random
    entry.key = "0".repeat(64);
    entry.key = crypto.randomBytes(32).toString("hex"); // Overwrite with garbage
    entry.destroyedAt = new Date().toISOString();
    this.save();

    console.log(`[KEYVAULT] Key destroyed: ${keyId.substring(0, 8)}...`);
    return true;
  }

  async getStats(): Promise<{
    totalKeys: number;
    byPurpose: Record<string, number>;
    byDerivation: Record<string, number>;
    provider: string;
  }> {
    const active = this.store.entries.filter(e => !e.destroyedAt);
    const byPurpose: Record<string, number> = {};
    const byDerivation: Record<string, number> = {};

    for (const e of active) {
      byPurpose[e.metadata.purpose] = (byPurpose[e.metadata.purpose] || 0) + 1;
      byDerivation[e.metadata.derivation] = (byDerivation[e.metadata.derivation] || 0) + 1;
    }

    return {
      totalKeys: active.length,
      byPurpose,
      byDerivation,
      provider: this.name,
    };
  }

  // ── Private ──────────────────────────────────────────────

  private findKey(keyId: string): LocalKeyEntry | undefined {
    return this.store.entries.find(e => e.keyId === keyId && !e.destroyedAt);
  }

  private load(): LocalVaultStore {
    if (fs.existsSync(this.storePath)) {
      try {
        const raw = fs.readFileSync(this.storePath, "utf-8");
        return JSON.parse(raw) as LocalVaultStore;
      } catch {
        console.warn("[KEYVAULT] Corrupt vault file — creating new one");
      }
    }
    return {
      engine: "Document Intelligence Engine",
      version: "5.0.0",
      warning: "SOVEREIGN KEY VAULT — CONTAINS ENCRYPTION KEYS. PROTECT ACCORDINGLY.",
      entries: [],
    };
  }

  private save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2), "utf-8");
  }
}

// ── HSMAdapter (Stub) ────────────────────────────────────────

/**
 * Hardware Security Module adapter stub.
 * Keys never leave the HSM boundary.
 *
 * In production, implement via:
 *   - PKCS#11 interface (SoftHSM, Thales, AWS CloudHSM)
 *   - AWS KMS SDK
 *   - Azure Key Vault SDK
 *   - Google Cloud KMS SDK
 *
 * This stub demonstrates the interface contract.
 * All operations throw until connected to a real HSM.
 */
export class HSMAdapter implements KeyProvider {
  readonly name = "hsm";
  readonly extractable = false;

  private connectionString: string;
  private connected = false;

  constructor(connectionString: string = "") {
    this.connectionString = connectionString;
  }

  private assertConnected(): void {
    if (!this.connected) {
      throw new Error("[HSM] Not connected. Configure HSM connection before use.");
    }
  }

  async connect(): Promise<boolean> {
    // In production: establish PKCS#11 session or SDK connection
    if (!this.connectionString) {
      console.warn("[HSM] No connection string provided. HSM adapter is in stub mode.");
      return false;
    }
    // Placeholder — connect to real HSM here
    this.connected = true;
    console.log("[HSM] Connected to HSM.");
    return true;
  }

  async generateKey(params: {
    purpose: KeyPurpose;
    derivation: KeyDerivation;
    documentId?: string;
    sku?: string;
  }): Promise<KeyMetadata> {
    this.assertConnected();
    // In production: HSM generates key internally, returns handle ID
    const keyId = `hsm-${crypto.randomBytes(16).toString("hex")}`;
    return {
      keyId,
      derivation: "hsm-managed",
      purpose: params.purpose,
      documentId: params.documentId,
      sku: params.sku,
      createdAt: new Date().toISOString(),
      extractable: false,
      provider: this.name,
      algorithm: "aes-256-gcm",
      keyLengthBits: 256,
    };
  }

  async encrypt(keyId: string, plaintext: Buffer): Promise<KeyProviderEncryptResult> {
    this.assertConnected();
    // In production: send plaintext to HSM, HSM encrypts with key handle
    throw new Error("[HSM] encrypt() — implement with HSM SDK");
  }

  async decrypt(keyId: string, params: {
    ciphertext: string;
    iv: string;
    authTag: string;
    expectedHash?: string;
  }): Promise<KeyProviderDecryptResult> {
    this.assertConnected();
    throw new Error("[HSM] decrypt() — implement with HSM SDK");
  }

  async sign(keyId: string, hash: string): Promise<KeyProviderSignResult> {
    this.assertConnected();
    throw new Error("[HSM] sign() — implement with HSM SDK");
  }

  async verify(keyId: string, hash: string, signature: string): Promise<boolean> {
    this.assertConnected();
    throw new Error("[HSM] verify() — implement with HSM SDK");
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata | undefined> {
    this.assertConnected();
    // In production: query HSM for key metadata
    return undefined;
  }

  async listKeys(filter?: { documentId?: string; purpose?: KeyPurpose }): Promise<KeyMetadata[]> {
    this.assertConnected();
    return [];
  }

  async rotateKey(oldKeyId: string): Promise<KeyMetadata> {
    this.assertConnected();
    throw new Error("[HSM] rotateKey() — implement with HSM SDK");
  }

  async destroyKey(keyId: string): Promise<boolean> {
    this.assertConnected();
    // In production: instruct HSM to securely destroy key
    throw new Error("[HSM] destroyKey() — implement with HSM SDK");
  }

  async getStats(): Promise<{
    totalKeys: number;
    byPurpose: Record<string, number>;
    byDerivation: Record<string, number>;
    provider: string;
  }> {
    return {
      totalKeys: 0,
      byPurpose: {},
      byDerivation: {},
      provider: this.name,
    };
  }
}

// ── Provider Registry ────────────────────────────────────────

/**
 * Global key provider registry.
 * The engine uses this to get the active provider.
 * Swap providers without touching any pipeline code.
 */
class KeyProviderRegistry {
  private providers: Map<string, KeyProvider> = new Map();
  private activeProvider: string = "local-vault";

  register(provider: KeyProvider): void {
    this.providers.set(provider.name, provider);
    console.log(`[KEY] Registered provider: ${provider.name}`);
  }

  setActive(name: string): void {
    if (!this.providers.has(name)) {
      throw new Error(`[KEY] Provider not found: ${name}. Registered: ${[...this.providers.keys()].join(", ")}`);
    }
    this.activeProvider = name;
    console.log(`[KEY] Active provider: ${name}`);
  }

  getActive(): KeyProvider {
    const provider = this.providers.get(this.activeProvider);
    if (!provider) {
      throw new Error(`[KEY] No active provider. Call register() first.`);
    }
    return provider;
  }

  getProvider(name: string): KeyProvider | undefined {
    return this.providers.get(name);
  }

  listProviders(): string[] {
    return [...this.providers.keys()];
  }
}

// ── Singleton ────────────────────────────────────────────────

let _registry: KeyProviderRegistry | null = null;

export function getKeyProviderRegistry(): KeyProviderRegistry {
  if (!_registry) {
    _registry = new KeyProviderRegistry();
    // Auto-register local vault as default
    _registry.register(new LocalVaultAdapter());
  }
  return _registry;
}

/**
 * Convenience: get the currently active key provider.
 */
export function getKeyProvider(): KeyProvider {
  return getKeyProviderRegistry().getActive();
}
