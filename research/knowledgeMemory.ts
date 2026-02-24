// ─────────────────────────────────────────────────────────────
// Knowledge Memory Layer — Persistent Intellectual State
//
// Every new paper, agreement, or analysis builds on top of
// accumulated knowledge. This module stores, indexes, searches,
// and cross-references all prior research artifacts.
//
// Persistence: .doc-engine/knowledge-memory.json
// Each ingested document becomes a ResearchMemoryNode.
// Supports: PDF, DOCX, HTML, TXT, MD ingestion.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";
import {
  ResearchMemoryNode,
  KnowledgeSourceType,
  EvidenceFragment,
  Citation,
  VersionEntry,
} from "../schema/researchSchema";
import { ingestDocument } from "../ingest/index";

// ── Constants ────────────────────────────────────────────────

const MEMORY_FILE = "knowledge-memory.json";

interface KnowledgeMemoryStore {
  engine: string;
  version: string;
  createdAt: string;
  lastUpdated: string;
  nodes: ResearchMemoryNode[];
}

// ── Knowledge Memory ─────────────────────────────────────────

export class KnowledgeMemory {
  private store: KnowledgeMemoryStore;
  private storePath: string;

  constructor(storeDir: string) {
    this.storePath = path.join(storeDir, MEMORY_FILE);
    this.store = this.load();
  }

  // ── Persistence ──────────────────────────────────────────

  private load(): KnowledgeMemoryStore {
    if (fs.existsSync(this.storePath)) {
      try {
        const raw = fs.readFileSync(this.storePath, "utf-8");
        return JSON.parse(raw);
      } catch {
        // Corrupted — start fresh
      }
    }
    return {
      engine: "Document Intelligence Engine — Knowledge Memory",
      version: "1.0.0",
      createdAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      nodes: [],
    };
  }

  private save(): void {
    this.store.lastUpdated = new Date().toISOString();
    const dir = path.dirname(this.storePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2), "utf-8");
  }

  // ── Ingest ─────────────────────────────────────────────────

  /**
   * Ingest a document file into knowledge memory.
   * Uses the existing ingest pipeline to extract text,
   * then builds a ResearchMemoryNode from the content.
   */
  async ingestFile(
    filePath: string,
    options: {
      topic?: string;
      sourceType?: KnowledgeSourceType;
      keywords?: string[];
      metadata?: Record<string, string>;
    } = {}
  ): Promise<ResearchMemoryNode> {
    const absolutePath = path.resolve(filePath);
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`Knowledge memory ingest: file not found — ${absolutePath}`);
    }

    // Use existing ingest pipeline
    const ingestResult = await ingestDocument(absolutePath);
    const content = ingestResult.rawText;
    const contentHash = crypto.createHash("sha256").update(content).digest("hex");

    // Check for duplicate
    const existing = this.store.nodes.find((n) => n.contentHash === contentHash);
    if (existing) {
      existing.lastAccessed = new Date().toISOString();
      this.save();
      return existing;
    }

    // Auto-detect topic and keywords from content
    const detectedTopic = options.topic || this.detectTopic(content, path.basename(absolutePath));
    const detectedKeywords = options.keywords || this.extractKeywords(content);
    const sourceType = options.sourceType || this.detectSourceType(content, path.basename(absolutePath));

    // Build node
    const nodeId = crypto.createHash("sha256")
      .update(absolutePath + Date.now().toString())
      .digest("hex")
      .substring(0, 16);

    const now = new Date().toISOString();

    const node: ResearchMemoryNode = {
      nodeId,
      title: this.extractTitle(content, path.basename(absolutePath)),
      sourceType,
      topic: detectedTopic,
      keywords: detectedKeywords,
      content,
      summary: this.generateSummary(content),
      supportingEvidence: this.extractEvidence(content),
      citations: this.extractCitations(content),
      crossReferences: [],
      sourceFile: absolutePath,
      contentHash,
      ingestedAt: now,
      lastAccessed: now,
      versionHistory: [
        {
          version: "1.0",
          timestamp: now,
          action: "created",
          description: `Ingested from ${path.basename(absolutePath)}`,
          contentHash,
        },
      ],
      metadata: options.metadata || {},
    };

    // Auto cross-reference with existing nodes
    node.crossReferences = this.findCrossReferences(node);

    this.store.nodes.push(node);
    this.save();

    return node;
  }

  /**
   * Ingest raw text content directly (not from a file).
   */
  ingestText(
    title: string,
    content: string,
    options: {
      topic?: string;
      sourceType?: KnowledgeSourceType;
      keywords?: string[];
      metadata?: Record<string, string>;
    } = {}
  ): ResearchMemoryNode {
    const contentHash = crypto.createHash("sha256").update(content).digest("hex");

    const existing = this.store.nodes.find((n) => n.contentHash === contentHash);
    if (existing) {
      existing.lastAccessed = new Date().toISOString();
      this.save();
      return existing;
    }

    const nodeId = crypto.createHash("sha256")
      .update(title + Date.now().toString())
      .digest("hex")
      .substring(0, 16);

    const now = new Date().toISOString();

    const node: ResearchMemoryNode = {
      nodeId,
      title,
      sourceType: options.sourceType || "prior-work",
      topic: options.topic || this.detectTopic(content, title),
      keywords: options.keywords || this.extractKeywords(content),
      content,
      summary: this.generateSummary(content),
      supportingEvidence: this.extractEvidence(content),
      citations: this.extractCitations(content),
      crossReferences: [],
      sourceFile: "direct-input",
      contentHash,
      ingestedAt: now,
      lastAccessed: now,
      versionHistory: [
        {
          version: "1.0",
          timestamp: now,
          action: "created",
          description: `Direct text ingestion: ${title}`,
          contentHash,
        },
      ],
      metadata: options.metadata || {},
    };

    node.crossReferences = this.findCrossReferences(node);
    this.store.nodes.push(node);
    this.save();

    return node;
  }

  // ── CRUD ───────────────────────────────────────────────────

  /** Get a node by ID */
  getNode(nodeId: string): ResearchMemoryNode | undefined {
    const node = this.store.nodes.find((n) => n.nodeId === nodeId);
    if (node) {
      node.lastAccessed = new Date().toISOString();
      this.save();
    }
    return node;
  }

  /** Get all nodes */
  getAllNodes(): ResearchMemoryNode[] {
    return [...this.store.nodes];
  }

  /** Update a node's content (creates version entry) */
  updateNode(nodeId: string, updates: Partial<Pick<ResearchMemoryNode, "title" | "topic" | "keywords" | "content" | "summary" | "metadata">>): ResearchMemoryNode | undefined {
    const node = this.store.nodes.find((n) => n.nodeId === nodeId);
    if (!node) return undefined;

    const prevHash = node.contentHash;

    if (updates.title) node.title = updates.title;
    if (updates.topic) node.topic = updates.topic;
    if (updates.keywords) node.keywords = updates.keywords;
    if (updates.metadata) node.metadata = { ...node.metadata, ...updates.metadata };

    if (updates.content) {
      node.content = updates.content;
      node.contentHash = crypto.createHash("sha256").update(updates.content).digest("hex");
      node.summary = updates.summary || this.generateSummary(updates.content);
      node.supportingEvidence = this.extractEvidence(updates.content);

      const nextVersion = (parseFloat(node.versionHistory[node.versionHistory.length - 1]?.version || "1.0") + 0.1).toFixed(1);
      node.versionHistory.push({
        version: nextVersion,
        timestamp: new Date().toISOString(),
        action: "updated",
        description: `Content updated (prev hash: ${prevHash.substring(0, 8)}...)`,
        contentHash: node.contentHash,
      });
    }

    node.lastAccessed = new Date().toISOString();
    this.save();
    return node;
  }

  /** Delete a node */
  deleteNode(nodeId: string): boolean {
    const idx = this.store.nodes.findIndex((n) => n.nodeId === nodeId);
    if (idx === -1) return false;

    // Remove cross-references pointing to this node
    for (const node of this.store.nodes) {
      node.crossReferences = node.crossReferences.filter((ref) => ref !== nodeId);
    }

    this.store.nodes.splice(idx, 1);
    this.save();
    return true;
  }

  // ── Search & Query ─────────────────────────────────────────

  /** Search nodes by keyword match across title, topic, keywords, and content */
  search(query: string, limit: number = 10): ResearchMemoryNode[] {
    const q = query.toLowerCase();
    const terms = q.split(/\s+/).filter(Boolean);

    const scored: { node: ResearchMemoryNode; score: number }[] = [];

    for (const node of this.store.nodes) {
      let score = 0;

      for (const term of terms) {
        // Title match (highest weight)
        if (node.title.toLowerCase().includes(term)) score += 10;
        // Topic match
        if (node.topic.toLowerCase().includes(term)) score += 8;
        // Keyword match
        if (node.keywords.some((k) => k.toLowerCase().includes(term))) score += 6;
        // Summary match
        if (node.summary.toLowerCase().includes(term)) score += 4;
        // Content match (lowest weight per occurrence)
        const contentLower = node.content.toLowerCase();
        const occurrences = (contentLower.match(new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length;
        score += Math.min(occurrences, 5) * 2;
      }

      if (score > 0) scored.push({ node, score });
    }

    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, limit).map((s) => s.node);
  }

  /** Find nodes by topic */
  findByTopic(topic: string): ResearchMemoryNode[] {
    const t = topic.toLowerCase();
    return this.store.nodes.filter(
      (n) => n.topic.toLowerCase().includes(t) || n.keywords.some((k) => k.toLowerCase().includes(t))
    );
  }

  /** Find nodes by source type */
  findBySourceType(sourceType: KnowledgeSourceType): ResearchMemoryNode[] {
    return this.store.nodes.filter((n) => n.sourceType === sourceType);
  }

  /** Get nodes that cross-reference a given node */
  getRelatedNodes(nodeId: string): ResearchMemoryNode[] {
    return this.store.nodes.filter(
      (n) => n.crossReferences.includes(nodeId) || n.nodeId === nodeId
    );
  }

  // ── Statistics ─────────────────────────────────────────────

  getStats(): {
    totalNodes: number;
    bySourceType: Record<string, number>;
    byTopic: Record<string, number>;
    totalEvidence: number;
    totalCitations: number;
    totalCrossRefs: number;
    oldestNode: string;
    newestNode: string;
  } {
    const bySourceType: Record<string, number> = {};
    const byTopic: Record<string, number> = {};
    let totalEvidence = 0;
    let totalCitations = 0;
    let totalCrossRefs = 0;
    let oldest = "";
    let newest = "";

    for (const node of this.store.nodes) {
      bySourceType[node.sourceType] = (bySourceType[node.sourceType] || 0) + 1;
      byTopic[node.topic] = (byTopic[node.topic] || 0) + 1;
      totalEvidence += node.supportingEvidence.length;
      totalCitations += node.citations.length;
      totalCrossRefs += node.crossReferences.length;

      if (!oldest || node.ingestedAt < oldest) oldest = node.ingestedAt;
      if (!newest || node.ingestedAt > newest) newest = node.ingestedAt;
    }

    return {
      totalNodes: this.store.nodes.length,
      bySourceType,
      byTopic,
      totalEvidence,
      totalCitations,
      totalCrossRefs,
      oldestNode: oldest,
      newestNode: newest,
    };
  }

  // ── Export ─────────────────────────────────────────────────

  /** Export all knowledge as a structured JSON package */
  exportKnowledgeBase(outputDir: string): string {
    const exportPath = path.join(outputDir, "knowledge-base-export.json");
    const exportData = {
      exportedAt: new Date().toISOString(),
      stats: this.getStats(),
      nodes: this.store.nodes,
    };
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(exportPath, JSON.stringify(exportData, null, 2), "utf-8");
    return exportPath;
  }

  /** Export a single node as a standalone package */
  exportNode(nodeId: string, outputDir: string): string | null {
    const node = this.getNode(nodeId);
    if (!node) return null;

    const exportPath = path.join(outputDir, `knowledge-node-${nodeId}.json`);
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(exportPath, JSON.stringify(node, null, 2), "utf-8");
    return exportPath;
  }

  // ── Internal Helpers ───────────────────────────────────────

  /** Extract a title from content or filename */
  private extractTitle(content: string, filename: string): string {
    // Try first non-empty line as title
    const lines = content.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length > 0) {
      const firstLine = lines[0].replace(/^#+\s*/, "").trim(); // strip markdown headers
      if (firstLine.length > 5 && firstLine.length < 200) {
        return firstLine;
      }
    }
    // Fall back to filename without extension
    return path.basename(filename, path.extname(filename));
  }

  /** Auto-detect topic from content */
  private detectTopic(content: string, filename: string): string {
    const lower = content.toLowerCase();
    const fnLower = filename.toLowerCase();

    const topicMap: [string[], string][] = [
      [["blockchain", "protocol", "consensus", "decentralized", "smart contract"], "Blockchain & Protocol Design"],
      [["finance", "bond", "securities", "investment", "structured finance", "ppp"], "Finance & Securities"],
      [["publishing", "literary", "manuscript", "deterministic"], "Publishing & Literary Systems"],
      [["dna", "sequence", "genetic", "genome", "nucleotide"], "DNA & Genomics"],
      [["sports", "betting", "wagering", "odds"], "Sports & Betting Analytics"],
      [["governance", "dao", "voting", "quorum"], "Governance & DAO"],
      [["compliance", "regulatory", "kyc", "aml"], "Compliance & Regulatory"],
      [["legal", "contract", "agreement", "nda", "terms"], "Legal & Contracts"],
      [["machine learning", "neural", "ai ", "artificial intelligence"], "AI & Machine Learning"],
      [["cryptography", "encryption", "hash", "signature"], "Cryptography & Security"],
      [["economics", "incentive", "tokenomics", "monetary"], "Economics & Tokenomics"],
    ];

    for (const [keywords, topic] of topicMap) {
      const matches = keywords.filter((k) => lower.includes(k) || fnLower.includes(k));
      if (matches.length >= 2) return topic;
    }

    // Single keyword fallback
    for (const [keywords, topic] of topicMap) {
      if (keywords.some((k) => lower.includes(k) || fnLower.includes(k))) return topic;
    }

    return "General Research";
  }

  /** Detect source type from content and filename */
  private detectSourceType(content: string, filename: string): KnowledgeSourceType {
    const lower = content.toLowerCase();
    const fnLower = filename.toLowerCase();

    if (lower.includes("abstract") && lower.includes("methodology")) return "research-paper";
    if (lower.includes("whitepaper") || lower.includes("white paper")) return "whitepaper";
    if (lower.includes("regulatory") || lower.includes("sec filing")) return "regulatory-filing";
    if (lower.includes("protocol") && lower.includes("architecture")) return "protocol-design";
    if (lower.includes("specification") || lower.includes("technical spec")) return "technical-spec";
    if (lower.includes("agreement") || lower.includes("contract") || lower.includes("nda")) return "legal-document";
    if (lower.includes("financial model") || lower.includes("financial mechanics")) return "financial-model";
    if (fnLower.includes("code") || lower.includes("function") && lower.includes("return")) return "technical-spec";

    return "prior-work";
  }

  /** Extract keywords from content */
  private extractKeywords(content: string): string[] {
    const lower = content.toLowerCase();

    // Domain-specific keyword candidates
    const candidateKeywords = [
      "blockchain", "protocol", "consensus", "smart contract", "decentralized",
      "deterministic", "publishing", "literary", "manuscript",
      "dna", "sequence", "genetic", "genome", "nucleotide",
      "finance", "bond", "securities", "structured finance", "ppp",
      "sports", "betting", "wagering", "analytics",
      "governance", "dao", "voting", "quorum", "proposal",
      "compliance", "regulatory", "kyc", "aml", "audit",
      "legal", "contract", "agreement", "nda", "terms",
      "cryptography", "encryption", "hash", "signature", "merkle",
      "ipfs", "cid", "immutable", "sovereignty",
      "api", "architecture", "system", "pipeline",
      "tokenomics", "economics", "incentive", "monetary",
      "risk", "security", "threat model", "vulnerability",
    ];

    const found: string[] = [];
    for (const kw of candidateKeywords) {
      if (lower.includes(kw)) found.push(kw);
    }

    // Limit to top 15
    return found.slice(0, 15);
  }

  /** Generate a summary from content (first ~500 chars of meaningful text) */
  private generateSummary(content: string): string {
    const lines = content
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 20); // skip short lines

    let summary = "";
    for (const line of lines) {
      if (summary.length + line.length > 800) break;
      summary += line + " ";
    }

    if (summary.length > 800) {
      summary = summary.substring(0, 797) + "...";
    }

    return summary.trim() || "No summary available.";
  }

  /** Extract evidence fragments from content */
  private extractEvidence(content: string): EvidenceFragment[] {
    const evidence: EvidenceFragment[] = [];
    const lines = content.split("\n");

    // Look for lines that contain strong claims, data points, or citations
    const evidencePatterns = [
      /\d+%/,                           // percentages
      /\$[\d,.]+/,                       // dollar amounts
      /\d{4}/,                           // years
      /\b(study|research|analysis|data|evidence|findings|results)\b/i,
      /\b(according to|demonstrates|proves|shows that|indicates)\b/i,
      /\b(theorem|proposition|corollary|lemma)\b/i,
    ];

    let fragmentCount = 0;
    for (let i = 0; i < lines.length && fragmentCount < 20; i++) {
      const line = lines[i].trim();
      if (line.length < 30) continue;

      for (const pattern of evidencePatterns) {
        if (pattern.test(line)) {
          evidence.push({
            fragmentId: crypto.createHash("sha256")
              .update(line)
              .digest("hex")
              .substring(0, 12),
            text: line.substring(0, 500),
            pageNumber: Math.floor(i / 40) + 1,  // approximate page
            confidence: 0.7,
            tags: this.extractKeywords(line).slice(0, 5),
          });
          fragmentCount++;
          break; // one fragment per line
        }
      }
    }

    return evidence;
  }

  /** Extract citation-like references from content */
  private extractCitations(content: string): Citation[] {
    const citations: Citation[] = [];

    // Look for common citation patterns
    const patterns = [
      // APA-like: Author (Year). Title.
      /([A-Z][a-z]+(?:\s(?:&|and)\s[A-Z][a-z]+)?)\s*\((\d{4})\)\.\s*([^.]+)\./g,
      // Numbered references: [1] Author, "Title"
      /\[(\d+)\]\s*([^,]+),\s*"([^"]+)"/g,
    ];

    const seenTitles = new Set<string>();

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null && citations.length < 20) {
        const title = (match[3] || match[2] || "").trim();
        if (title.length < 5 || seenTitles.has(title.toLowerCase())) continue;
        seenTitles.add(title.toLowerCase());

        citations.push({
          citationId: crypto.createHash("sha256")
            .update(title)
            .digest("hex")
            .substring(0, 12),
          type: "journal-article",
          authors: [match[1] || "Unknown"],
          title,
          year: parseInt(match[2] || "2025", 10),
          source: "Extracted from document",
        });
      }
    }

    return citations;
  }

  /** Find cross-references between this node and existing nodes */
  private findCrossReferences(newNode: ResearchMemoryNode): string[] {
    const refs: string[] = [];
    const newKeywords = new Set(newNode.keywords.map((k) => k.toLowerCase()));
    const newTopicLower = newNode.topic.toLowerCase();

    for (const existing of this.store.nodes) {
      if (existing.nodeId === newNode.nodeId) continue;

      let relevance = 0;

      // Topic match
      if (existing.topic.toLowerCase() === newTopicLower) relevance += 3;

      // Keyword overlap
      const overlap = existing.keywords.filter((k) => newKeywords.has(k.toLowerCase()));
      relevance += overlap.length;

      // Content cross-references (check if one mentions the other's title)
      if (newNode.content.toLowerCase().includes(existing.title.toLowerCase())) relevance += 5;
      if (existing.content.toLowerCase().includes(newNode.title.toLowerCase())) relevance += 5;

      if (relevance >= 3) {
        refs.push(existing.nodeId);
        // Also add reverse reference
        if (!existing.crossReferences.includes(newNode.nodeId)) {
          existing.crossReferences.push(newNode.nodeId);
        }
      }
    }

    return refs;
  }
}

// ── Singleton ────────────────────────────────────────────────

let _instance: KnowledgeMemory | null = null;

export function getKnowledgeMemory(storeDir?: string): KnowledgeMemory {
  if (!_instance) {
    const dir = storeDir || path.join(process.cwd(), ".doc-engine");
    _instance = new KnowledgeMemory(dir);
  }
  return _instance;
}
