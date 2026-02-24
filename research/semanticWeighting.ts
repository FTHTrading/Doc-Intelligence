// ─────────────────────────────────────────────────────────────
// Semantic Memory Weighting — Citation-Weighted Knowledge Scoring
//
// Upgrades the knowledge memory system with:
//
//   1. Citation-weighted scoring — nodes cited more have higher weight
//   2. Cross-document consensus — claims supported by multiple sources
//   3. Confidence decay — older nodes lose weight unless re-cited
//   4. Semantic similarity clustering (keyword-based)
//   5. Authority propagation — high-weight sources boost cited neighbors
//   6. Evidence density scoring
//
// This module computes and caches weights, does NOT mutate source nodes.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import fs from "fs";
import path from "path";
import {
  ResearchMemoryNode,
  EvidenceFragment,
  KnowledgeSourceType,
} from "../schema/researchSchema";
import { KnowledgeMemory, getKnowledgeMemory } from "./knowledgeMemory";

// ── Types ────────────────────────────────────────────────────

/** Per-node weight record */
export interface NodeWeight {
  nodeId: string;
  title: string;

  /** Final composite weight: 0-100 */
  compositeWeight: number;

  /** Individual scoring factors */
  factors: {
    /** How many other nodes cite this one */
    inboundCitations: number;
    /** How many citations this node makes */
    outboundCitations: number;
    /** Cross-document consensus (0-1): fraction of related nodes agreeing */
    consensus: number;
    /** Evidence density: evidence fragments per kilobyte */
    evidenceDensity: number;
    /** Confidence decay factor (1.0 = fresh, decreasing over time) */
    decayFactor: number;
    /** Authority propagation score (boosted by high-weight inbound) */
    authorityScore: number;
    /** Source type prestige (0-1) */
    sourceTypePrestige: number;
    /** Keyword relevance: overlap with top concepts */
    keywordRelevance: number;
  };

  /** When this weight was computed */
  computedAt: string;
}

/** Consensus cluster: group of nodes that agree on a claim */
export interface ConsensusCluster {
  clusterId: string;
  /** Shared concept or claim */
  concept: string;
  /** Participating nodes */
  nodeIds: string[];
  /** Consensus strength (0-1) */
  strength: number;
  /** Number of independent sources */
  independentSources: number;
  /** Conflicting nodes */
  dissenting: string[];
}

/** Memory weight report */
export interface MemoryWeightReport {
  generatedAt: string;
  totalNodes: number;
  weights: NodeWeight[];
  consensusClusters: ConsensusCluster[];
  topAuthorities: Array<{ nodeId: string; title: string; weight: number }>;
  decayedNodes: Array<{ nodeId: string; title: string; decay: number; daysSinceAccess: number }>;
  reportHash: string;
}

// ── Source Type Prestige ─────────────────────────────────────

const SOURCE_PRESTIGE: Record<string, number> = {
  "research-paper": 0.95,
  "whitepaper": 0.85,
  "regulatory-filing": 0.92,
  "technical-spec": 0.88,
  "legal-document": 0.90,
  "financial-model": 0.82,
  "protocol-design": 0.87,
  "field-notes": 0.60,
  "prior-work": 0.75,
  "external-reference": 0.65,
};

// ── Decay Configuration ─────────────────────────────────────

/** Half-life in days — after this many days without re-access, weight halves */
const DECAY_HALF_LIFE_DAYS = 90;
/** Minimum decay factor — weight never drops below this fraction */
const DECAY_FLOOR = 0.2;

// ── Weights for Composite Score ──────────────────────────────

const COMPOSITE_WEIGHTS = {
  inboundCitations: 0.25,
  consensus: 0.20,
  evidenceDensity: 0.15,
  authorityScore: 0.15,
  sourceTypePrestige: 0.10,
  keywordRelevance: 0.10,
  decayFactor: 0.05,
};

// ── Engine ───────────────────────────────────────────────────

const WEIGHTS_FILE = "memory-weights.json";

interface WeightStore {
  engine: string;
  version: string;
  computedAt: string;
  weights: NodeWeight[];
  consensusClusters: ConsensusCluster[];
}

export class SemanticMemoryWeightEngine {
  private store: WeightStore;
  private storePath: string;
  private memory: KnowledgeMemory;

  constructor(memory?: KnowledgeMemory, storeDir: string = ".doc-engine") {
    this.memory = memory || getKnowledgeMemory();
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    }
    this.storePath = path.join(storeDir, WEIGHTS_FILE);
    this.store = this.load();
  }

  // ── Core: Compute All Weights ─────────────────────────────

  /**
   * Recompute weights for all nodes in memory.
   * This is the main entry point — call after consolidation or on-demand.
   */
  computeWeights(): MemoryWeightReport {
    const nodes = this.memory.getAllNodes();
    if (nodes.length === 0) {
      return this.emptyReport();
    }

    // Phase 1: Build citation graph
    const inboundMap = this.buildInboundCitationMap(nodes);
    const keywordFrequency = this.buildKeywordFrequency(nodes);
    const topKeywords = this.getTopKeywords(keywordFrequency, 50);

    // Phase 2: Compute per-node raw factors
    const rawWeights: NodeWeight[] = nodes.map(node => {
      const inbound = inboundMap.get(node.nodeId) || [];
      const outbound = node.crossReferences.length + node.citations.length;
      const evidenceDensity = this.computeEvidenceDensity(node);
      const decayFactor = this.computeDecay(node);
      const sourceTypePrestige = SOURCE_PRESTIGE[node.sourceType] || 0.5;
      const keywordRelevance = this.computeKeywordRelevance(node, topKeywords);

      return {
        nodeId: node.nodeId,
        title: node.title,
        compositeWeight: 0, // computed in Phase 3
        factors: {
          inboundCitations: inbound.length,
          outboundCitations: outbound,
          consensus: 0, // computed in Phase 3
          evidenceDensity,
          decayFactor,
          authorityScore: 0, // computed in Phase 3
          sourceTypePrestige,
          keywordRelevance,
        },
        computedAt: new Date().toISOString(),
      };
    });

    // Phase 3: Consensus clustering
    const consensusClusters = this.buildConsensusClusters(nodes);

    // Assign consensus scores
    for (const weight of rawWeights) {
      const clusters = consensusClusters.filter(c => c.nodeIds.includes(weight.nodeId));
      if (clusters.length > 0) {
        weight.factors.consensus = clusters.reduce((max, c) => Math.max(max, c.strength), 0);
      }
    }

    // Phase 4: Authority propagation (1 iteration of PageRank-like)
    this.propagateAuthority(rawWeights, inboundMap);

    // Phase 5: Compute composite scores
    for (const weight of rawWeights) {
      weight.compositeWeight = this.computeComposite(weight);
    }

    // Sort by weight descending
    rawWeights.sort((a, b) => b.compositeWeight - a.compositeWeight);

    // Build report
    const topAuthorities = rawWeights.slice(0, 10).map(w => ({
      nodeId: w.nodeId,
      title: w.title,
      weight: w.compositeWeight,
    }));

    const decayedNodes = rawWeights
      .filter(w => w.factors.decayFactor < 0.7)
      .map(w => {
        const node = nodes.find(n => n.nodeId === w.nodeId);
        const daysSinceAccess = node
          ? (Date.now() - new Date(node.lastAccessed).getTime()) / (1000 * 60 * 60 * 24)
          : 0;
        return {
          nodeId: w.nodeId,
          title: w.title,
          decay: w.factors.decayFactor,
          daysSinceAccess: Math.round(daysSinceAccess),
        };
      });

    const reportBody = {
      totalNodes: nodes.length,
      weights: rawWeights,
      consensusClusters,
      topAuthorities,
      decayedNodes,
    };

    const reportHash = crypto
      .createHash("sha256")
      .update(JSON.stringify(reportBody))
      .digest("hex");

    const report: MemoryWeightReport = {
      generatedAt: new Date().toISOString(),
      ...reportBody,
      reportHash,
    };

    // Persist
    this.store = {
      engine: "Document Intelligence Engine",
      version: "5.0.0",
      computedAt: report.generatedAt,
      weights: rawWeights,
      consensusClusters,
    };
    this.save();

    return report;
  }

  // ── Query ─────────────────────────────────────────────────

  /**
   * Get the weight for a specific node.
   */
  getWeight(nodeId: string): NodeWeight | undefined {
    return this.store.weights.find(w => w.nodeId === nodeId);
  }

  /**
   * Get the top N nodes by weight.
   */
  getTopNodes(n: number = 10): NodeWeight[] {
    return this.store.weights.slice(0, n);
  }

  /**
   * Query nodes by minimum weight threshold.
   */
  getAboveThreshold(minWeight: number): NodeWeight[] {
    return this.store.weights.filter(w => w.compositeWeight >= minWeight);
  }

  /**
   * Get consensus clusters.
   */
  getConsensusClusters(): ConsensusCluster[] {
    return this.store.consensusClusters;
  }

  /**
   * Get the weight-adjusted search results.
   * Takes search results (nodeIds) and re-ranks by composite weight.
   */
  weightedSearch(nodeIds: string[]): NodeWeight[] {
    return nodeIds
      .map(id => this.store.weights.find(w => w.nodeId === id))
      .filter((w): w is NodeWeight => !!w)
      .sort((a, b) => b.compositeWeight - a.compositeWeight);
  }

  // ── Computation Helpers ───────────────────────────────────

  /**
   * Build a map: nodeId → list of node IDs that cite it.
   */
  private buildInboundCitationMap(nodes: ResearchMemoryNode[]): Map<string, string[]> {
    const map = new Map<string, string[]>();
    for (const node of nodes) {
      map.set(node.nodeId, []);
    }
    for (const node of nodes) {
      for (const ref of node.crossReferences) {
        const list = map.get(ref);
        if (list && !list.includes(node.nodeId)) {
          list.push(node.nodeId);
        }
      }
    }
    return map;
  }

  /**
   * Build keyword frequency map across all nodes.
   */
  private buildKeywordFrequency(nodes: ResearchMemoryNode[]): Map<string, number> {
    const freq = new Map<string, number>();
    for (const node of nodes) {
      for (const kw of node.keywords) {
        const normalized = kw.toLowerCase().trim();
        freq.set(normalized, (freq.get(normalized) || 0) + 1);
      }
    }
    return freq;
  }

  /**
   * Get the top N keywords by frequency.
   */
  private getTopKeywords(freq: Map<string, number>, n: number): Set<string> {
    const sorted = [...freq.entries()].sort((a, b) => b[1] - a[1]);
    return new Set(sorted.slice(0, n).map(([kw]) => kw));
  }

  /**
   * Compute evidence density: fragments per kilobyte of content.
   */
  private computeEvidenceDensity(node: ResearchMemoryNode): number {
    const contentKB = Math.max(Buffer.byteLength(node.content, "utf-8") / 1024, 0.1);
    const fragmentCount = node.supportingEvidence.length;
    // Normalize: assume 1 fragment per KB is baseline (1.0)
    return Math.min(fragmentCount / contentKB, 5.0) / 5.0;
  }

  /**
   * Compute exponential decay based on lastAccessed timestamp.
   */
  private computeDecay(node: ResearchMemoryNode): number {
    const daysSinceAccess = (Date.now() - new Date(node.lastAccessed).getTime()) / (1000 * 60 * 60 * 24);
    // Exponential decay: factor = 2^(-days/halfLife)
    const rawDecay = Math.pow(2, -daysSinceAccess / DECAY_HALF_LIFE_DAYS);
    return Math.max(rawDecay, DECAY_FLOOR);
  }

  /**
   * Compute keyword relevance: fraction of node's keywords in top global keywords.
   */
  private computeKeywordRelevance(node: ResearchMemoryNode, topKeywords: Set<string>): number {
    if (node.keywords.length === 0) return 0;
    const matches = node.keywords.filter(kw => topKeywords.has(kw.toLowerCase().trim())).length;
    return matches / node.keywords.length;
  }

  /**
   * Build consensus clusters: groups of nodes sharing significant keyword overlap.
   */
  private buildConsensusClusters(nodes: ResearchMemoryNode[]): ConsensusCluster[] {
    const clusters: ConsensusCluster[] = [];
    const visited = new Set<string>();

    // Group by shared keywords (minimum 2 shared keywords = cluster candidate)
    for (let i = 0; i < nodes.length; i++) {
      if (visited.has(nodes[i].nodeId)) continue;

      const cluster: string[] = [nodes[i].nodeId];
      const clusterKeywords = new Set(nodes[i].keywords.map(k => k.toLowerCase().trim()));

      for (let j = i + 1; j < nodes.length; j++) {
        if (visited.has(nodes[j].nodeId)) continue;

        const otherKeywords = nodes[j].keywords.map(k => k.toLowerCase().trim());
        const overlap = otherKeywords.filter(k => clusterKeywords.has(k)).length;

        if (overlap >= 2) {
          cluster.push(nodes[j].nodeId);
          for (const k of otherKeywords) clusterKeywords.add(k);
        }
      }

      if (cluster.length >= 2) {
        for (const id of cluster) visited.add(id);

        // Compute strength based on cross-references within cluster
        let internalRefs = 0;
        for (const id of cluster) {
          const node = nodes.find(n => n.nodeId === id);
          if (node) {
            internalRefs += node.crossReferences.filter(r => cluster.includes(r)).length;
          }
        }
        const maxPossibleRefs = cluster.length * (cluster.length - 1);
        const strength = maxPossibleRefs > 0 ? internalRefs / maxPossibleRefs : 0;

        // Find dissenting nodes (nodes with overlapping keywords but contradictory evidence)
        const conceptLabel = [...clusterKeywords].slice(0, 3).join(", ");
        const uniqueSources = new Set(cluster.map(id => {
          const n = nodes.find(nn => nn.nodeId === id);
          return n ? n.sourceFile : "";
        })).size;

        clusters.push({
          clusterId: crypto.randomBytes(8).toString("hex"),
          concept: conceptLabel,
          nodeIds: cluster,
          strength: Math.min(0.3 + strength * 0.7 + (cluster.length / nodes.length) * 0.3, 1.0),
          independentSources: uniqueSources,
          dissenting: [],
        });
      }
    }

    return clusters;
  }

  /**
   * Single-pass authority propagation (simplified PageRank).
   * Nodes cited by high-inbound nodes get an authority boost.
   */
  private propagateAuthority(weights: NodeWeight[], inboundMap: Map<string, string[]>): void {
    // First pass: set base authority from inbound count
    const maxInbound = Math.max(1, ...weights.map(w => w.factors.inboundCitations));
    for (const w of weights) {
      w.factors.authorityScore = w.factors.inboundCitations / maxInbound;
    }

    // Second pass: boost authority from high-authority inbound nodes
    for (const w of weights) {
      const inbound = inboundMap.get(w.nodeId) || [];
      if (inbound.length === 0) continue;

      let boost = 0;
      for (const citerId of inbound) {
        const citer = weights.find(ww => ww.nodeId === citerId);
        if (citer) {
          boost += citer.factors.authorityScore * 0.15; // dampening factor
        }
      }
      w.factors.authorityScore = Math.min(w.factors.authorityScore + boost, 1.0);
    }
  }

  /**
   * Compute composite weight from individual factors.
   */
  private computeComposite(weight: NodeWeight): number {
    const f = weight.factors;
    const maxInbound = 10; // normalize inbound citations to 0-1 range

    const normalizedFactors = {
      inboundCitations: Math.min(f.inboundCitations / maxInbound, 1.0),
      consensus: f.consensus,
      evidenceDensity: f.evidenceDensity,
      authorityScore: f.authorityScore,
      sourceTypePrestige: f.sourceTypePrestige,
      keywordRelevance: f.keywordRelevance,
      decayFactor: f.decayFactor,
    };

    let weighted = 0;
    weighted += normalizedFactors.inboundCitations * COMPOSITE_WEIGHTS.inboundCitations;
    weighted += normalizedFactors.consensus * COMPOSITE_WEIGHTS.consensus;
    weighted += normalizedFactors.evidenceDensity * COMPOSITE_WEIGHTS.evidenceDensity;
    weighted += normalizedFactors.authorityScore * COMPOSITE_WEIGHTS.authorityScore;
    weighted += normalizedFactors.sourceTypePrestige * COMPOSITE_WEIGHTS.sourceTypePrestige;
    weighted += normalizedFactors.keywordRelevance * COMPOSITE_WEIGHTS.keywordRelevance;
    weighted += normalizedFactors.decayFactor * COMPOSITE_WEIGHTS.decayFactor;

    return Math.round(weighted * 100 * 100) / 100; // 0-100, two decimal places
  }

  // ── Report Formatting ─────────────────────────────────────

  /**
   * Format a weight report as human-readable text.
   */
  formatReport(report: MemoryWeightReport): string {
    const lines: string[] = [];
    lines.push(`╔══════════════════════════════════════════════════════╗`);
    lines.push(`║  SEMANTIC MEMORY WEIGHT REPORT                      ║`);
    lines.push(`╚══════════════════════════════════════════════════════╝`);
    lines.push(``);
    lines.push(`  Nodes analyzed: ${report.totalNodes}`);
    lines.push(`  Computed: ${report.generatedAt}`);
    lines.push(`  Report hash: ${report.reportHash.substring(0, 32)}...`);
    lines.push(``);

    if (report.topAuthorities.length > 0) {
      lines.push(`  ─── Top Authorities ──────────────────────────────`);
      for (const auth of report.topAuthorities) {
        lines.push(`  [${auth.weight.toFixed(1)}] ${auth.title}`);
      }
      lines.push(``);
    }

    if (report.consensusClusters.length > 0) {
      lines.push(`  ─── Consensus Clusters (${report.consensusClusters.length}) ──────────────`);
      for (const c of report.consensusClusters) {
        lines.push(`  [${(c.strength * 100).toFixed(0)}%] "${c.concept}" — ${c.nodeIds.length} nodes, ${c.independentSources} sources`);
      }
      lines.push(``);
    }

    if (report.decayedNodes.length > 0) {
      lines.push(`  ─── Decayed Nodes (${report.decayedNodes.length}) ─────────────────────`);
      for (const d of report.decayedNodes) {
        lines.push(`  [${(d.decay * 100).toFixed(0)}%] ${d.title} — ${d.daysSinceAccess} days stale`);
      }
      lines.push(``);
    }

    return lines.join("\n");
  }

  // ── Persistence ───────────────────────────────────────────

  private load(): WeightStore {
    if (fs.existsSync(this.storePath)) {
      try {
        return JSON.parse(fs.readFileSync(this.storePath, "utf-8")) as WeightStore;
      } catch {
        console.warn("[WEIGHT] Corrupt store — creating new one");
      }
    }
    return {
      engine: "Document Intelligence Engine",
      version: "5.0.0",
      computedAt: "",
      weights: [],
      consensusClusters: [],
    };
  }

  private save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.store, null, 2), "utf-8");
  }

  private emptyReport(): MemoryWeightReport {
    return {
      generatedAt: new Date().toISOString(),
      totalNodes: 0,
      weights: [],
      consensusClusters: [],
      topAuthorities: [],
      decayedNodes: [],
      reportHash: crypto.createHash("sha256").update("empty").digest("hex"),
    };
  }
}

// ── Singleton ────────────────────────────────────────────────

let _weightEngine: SemanticMemoryWeightEngine | null = null;

export function getMemoryWeightEngine(memory?: KnowledgeMemory): SemanticMemoryWeightEngine {
  if (!_weightEngine) {
    _weightEngine = new SemanticMemoryWeightEngine(memory);
  }
  return _weightEngine;
}
