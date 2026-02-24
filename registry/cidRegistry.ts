// ─────────────────────────────────────────────────────────────
// CID Registry — DocumentID → CID → MerkleRoot → Author → Sig
// Persistent local registry mapping sovereign document identity
// to IPFS content identifiers with full provenance metadata.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";

/** A single registry entry mapping a document to its CID */
export interface CIDRecord {
  /** Internal document ID (UUID) */
  documentId: string;
  /** Document SKU (human-readable identity code) */
  sku: string;
  /** IPFS Content Identifier */
  cid: string;
  /** Merkle root of document sections */
  merkleRoot: string;
  /** SHA-256 hash of document */
  sha256: string;
  /** Author / signer identity */
  author: string;
  /** ISO timestamp of registration */
  registeredAt: string;
  /** Digital signature of the record (sha256 of payload) */
  signature: string;
  /** Blockchain anchor chain (if anchored) */
  chain?: string;
  /** On-chain transaction hash (if anchored) */
  transactionHash?: string;
  /** Document version */
  version: string;
  /** Source filename */
  sourceFile: string;
  /** Additional metadata */
  metadata: Record<string, string>;
}

/** Registry query result */
export interface RegistryLookup {
  found: boolean;
  record?: CIDRecord;
  allVersions?: CIDRecord[];
}

/** Registry statistics */
export interface RegistryStats {
  totalRecords: number;
  uniqueDocuments: number;
  totalSize: number;
  oldestEntry: string;
  newestEntry: string;
  chains: Record<string, number>;
}

/** Full registry data structure (persisted to disk) */
interface RegistryStore {
  engine: string;
  version: string;
  createdAt: string;
  lastUpdated: string;
  records: CIDRecord[];
}

const REGISTRY_FILE = "cid-registry.json";

export class CIDRegistry {
  private store: RegistryStore;
  private registryPath: string;

  constructor(registryDir: string) {
    this.registryPath = path.join(registryDir, REGISTRY_FILE);
    this.store = this.load();
  }

  /** Load registry from disk (or create empty one) */
  private load(): RegistryStore {
    if (fs.existsSync(this.registryPath)) {
      try {
        const raw = fs.readFileSync(this.registryPath, "utf-8");
        return JSON.parse(raw) as RegistryStore;
      } catch {
        console.warn("[REGISTRY] Corrupt registry file — creating new one");
      }
    }
    return {
      engine: "Document Intelligence Engine",
      version: "1.0.0",
      createdAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      records: [],
    };
  }

  /** Persist registry to disk */
  private save(): void {
    const dir = path.dirname(this.registryPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    this.store.lastUpdated = new Date().toISOString();
    fs.writeFileSync(this.registryPath, JSON.stringify(this.store, null, 2), "utf-8");
  }

  /** Generate a record signature (hash of payload fields) */
  private signRecord(record: Omit<CIDRecord, "signature">): string {
    const payload = `${record.documentId}:${record.cid}:${record.merkleRoot}:${record.sha256}:${record.author}:${record.registeredAt}`;
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  /** Register a new CID record */
  register(params: {
    documentId: string;
    sku: string;
    cid: string;
    merkleRoot: string;
    sha256: string;
    author: string;
    chain?: string;
    transactionHash?: string;
    version: string;
    sourceFile: string;
    metadata?: Record<string, string>;
  }): CIDRecord {
    const record: Omit<CIDRecord, "signature"> = {
      documentId: params.documentId,
      sku: params.sku,
      cid: params.cid,
      merkleRoot: params.merkleRoot,
      sha256: params.sha256,
      author: params.author,
      registeredAt: new Date().toISOString(),
      chain: params.chain,
      transactionHash: params.transactionHash,
      version: params.version,
      sourceFile: params.sourceFile,
      metadata: params.metadata || {},
    };

    const signature = this.signRecord(record);
    const fullRecord: CIDRecord = { ...record, signature };

    this.store.records.push(fullRecord);
    this.save();

    console.log(`[REGISTRY] Registered: ${params.sku} → ${params.cid}`);
    return fullRecord;
  }

  /** Look up a record by CID */
  lookupByCID(cid: string): RegistryLookup {
    const record = this.store.records.find((r) => r.cid === cid);
    if (!record) return { found: false };

    const allVersions = this.store.records.filter(
      (r) => r.documentId === record.documentId
    );
    return { found: true, record, allVersions };
  }

  /** Look up a record by document ID */
  lookupByDocumentId(documentId: string): RegistryLookup {
    const records = this.store.records.filter(
      (r) => r.documentId === documentId
    );
    if (records.length === 0) return { found: false };

    // Return the latest version
    const sorted = records.sort(
      (a, b) => new Date(b.registeredAt).getTime() - new Date(a.registeredAt).getTime()
    );
    return { found: true, record: sorted[0], allVersions: sorted };
  }

  /** Look up a record by SKU */
  lookupBySKU(sku: string): RegistryLookup {
    const records = this.store.records.filter((r) => r.sku === sku);
    if (records.length === 0) return { found: false };

    const sorted = records.sort(
      (a, b) => new Date(b.registeredAt).getTime() - new Date(a.registeredAt).getTime()
    );
    return { found: true, record: sorted[0], allVersions: sorted };
  }

  /** Look up by SHA-256 hash */
  lookupByHash(sha256: string): RegistryLookup {
    const record = this.store.records.find((r) => r.sha256 === sha256);
    if (!record) return { found: false };
    return { found: true, record };
  }

  /** Verify a record's signature integrity */
  verifyRecord(record: CIDRecord): boolean {
    const { signature, ...rest } = record;
    const recomputed = this.signRecord(rest);
    return recomputed === signature;
  }

  /** List all records */
  listAll(): CIDRecord[] {
    return [...this.store.records];
  }

  /** List records by author */
  listByAuthor(author: string): CIDRecord[] {
    return this.store.records.filter(
      (r) => r.author.toLowerCase() === author.toLowerCase()
    );
  }

  /** Get registry statistics */
  getStats(): RegistryStats {
    const records = this.store.records;
    if (records.length === 0) {
      return {
        totalRecords: 0,
        uniqueDocuments: 0,
        totalSize: 0,
        oldestEntry: "",
        newestEntry: "",
        chains: {},
      };
    }

    const uniqueDocs = new Set(records.map((r) => r.documentId));
    const chains: Record<string, number> = {};
    for (const r of records) {
      if (r.chain) {
        chains[r.chain] = (chains[r.chain] || 0) + 1;
      }
    }

    const sorted = records.sort(
      (a, b) => new Date(a.registeredAt).getTime() - new Date(b.registeredAt).getTime()
    );

    let totalSize = 0;
    try {
      const stat = fs.statSync(this.registryPath);
      totalSize = stat.size;
    } catch {}

    return {
      totalRecords: records.length,
      uniqueDocuments: uniqueDocs.size,
      totalSize,
      oldestEntry: sorted[0].registeredAt,
      newestEntry: sorted[sorted.length - 1].registeredAt,
      chains,
    };
  }

  /** Export registry to standalone JSON file */
  exportTo(outputPath: string): void {
    fs.writeFileSync(outputPath, JSON.stringify(this.store, null, 2), "utf-8");
    console.log(`[REGISTRY] Exported → ${outputPath}`);
  }
}

/** Singleton registry instance */
let _registry: CIDRegistry | null = null;

export function getRegistry(registryDir?: string): CIDRegistry {
  if (!_registry) {
    const dir = registryDir || path.join(process.cwd(), ".doc-engine");
    _registry = new CIDRegistry(dir);
  }
  return _registry;
}
