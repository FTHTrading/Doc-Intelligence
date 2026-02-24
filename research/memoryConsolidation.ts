// ─────────────────────────────────────────────────────────────
// Memory Consolidation Engine — Knowledge Graph Hardening
//
// Transforms raw knowledge memory from a flat list of
// ingested nodes into a structured, deduplicated, cross-
// referenced, confidence-scored knowledge graph.
//
// Capabilities:
//   1. Duplicate detection & merge
//   2. Domain clustering (auto-group by topic)
//   3. Citation normalization & deduplication
//   4. Cross-reference integrity verification
//   5. Evidence contradiction detection
//   6. Source confidence scoring
//   7. Concept extraction & frequency analysis
//   8. Consolidation report generation
//
// This is the brain's defragmentation layer.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import {
  ResearchMemoryNode,
  EvidenceFragment,
  Citation,
} from "../schema/researchSchema";
import { KnowledgeMemory } from "./knowledgeMemory";

// ── Types ────────────────────────────────────────────────────

/** A cluster of related knowledge nodes */
export interface DomainCluster {
  clusterId: string;
  domain: string;
  keywords: string[];
  nodeIds: string[];
  nodeCount: number;
  totalEvidence: number;
  totalCitations: number;
  confidence: number; // 0-1 aggregate confidence
  coherence: number;  // 0-1 how tightly related the nodes are
}

/** Duplicate detection result */
export interface DuplicateGroup {
  /** Primary (canonical) node ID */
  primaryNodeId: string;
  /** Duplicate node IDs */
  duplicateNodeIds: string[];
  /** Similarity score (0-1) */
  similarity: number;
  /** Method of duplicate detection */
  method: "exact-hash" | "title-match" | "content-similarity" | "citation-overlap";
}

/** Evidence contradiction */
export interface Contradiction {
  /** ID of first evidence fragment */
  evidenceA: { nodeId: string; fragmentId: string; text: string };
  /** ID of second evidence fragment */
  evidenceB: { nodeId: string; fragmentId: string; text: string };
  /** Type of contradiction */
  type: "factual" | "statistical" | "temporal" | "terminological";
  /** Description */
  description: string;
  /** Severity (0-1) */
  severity: number;
}

/** Source confidence score */
export interface SourceConfidence {
  nodeId: string;
  title: string;
  /** Overall confidence score (0-100) */
  score: number;
  /** Breakdown */
  factors: {
    /** Has citations (weighted) */
    citationPresence: number;
    /** Cross-referenced by other nodes */
    crossReferenceCount: number;
    /** Evidence fragment quality */
    evidenceQuality: number;
    /** Content length factor */
    contentDepth: number;
    /** Recency bonus */
    recency: number;
    /** Source type weight */
    sourceTypeWeight: number;
  };
}

/** Cross-reference integrity report */
export interface CrossRefIntegrity {
  /** Total cross-references found */
  totalRefs: number;
  /** Valid references (target node exists) */
  validRefs: number;
  /** Broken references (target node missing) */
  brokenRefs: string[];
  /** Orphan nodes (no incoming or outgoing refs) */
  orphanNodes: string[];
  /** Bidirectional consistency */
  bidirectionalMissing: Array<{ from: string; to: string }>;
}

/** Concept frequency entry */
export interface ConceptFrequency {
  concept: string;
  frequency: number;
  nodeIds: string[];
  evidenceCount: number;
}

/** Full consolidation report */
export interface ConsolidationReport {
  /** Report timestamp */
  generatedAt: string;
  /** Knowledge base stats */
  stats: {
    totalNodes: number;
    totalEvidence: number;
    totalCitations: number;
    totalCrossRefs: number;
  };
  /** Domain clusters */
  clusters: DomainCluster[];
  /** Detected duplicates */
  duplicates: DuplicateGroup[];
  /** Contradictions detected */
  contradictions: Contradiction[];
  /** Source confidence scores */
  confidenceScores: SourceConfidence[];
  /** Cross-reference integrity */
  crossRefIntegrity: CrossRefIntegrity;
  /** Top concepts */
  topConcepts: ConceptFrequency[];
  /** Actions taken */
  actions: ConsolidationAction[];
  /** Report hash */
  reportHash: string;
}

/** An action taken during consolidation */
export interface ConsolidationAction {
  type: "merged-duplicate" | "fixed-cross-ref" | "added-cross-ref" | "normalized-citation" | "flagged-contradiction" | "scored-confidence";
  description: string;
  affectedNodeIds: string[];
  timestamp: string;
}

// ── Source Type Weights ──────────────────────────────────────

const SOURCE_TYPE_WEIGHTS: Record<string, number> = {
  "research-paper": 0.95,
  "whitepaper": 0.85,
  "regulatory-filing": 0.90,
  "technical-spec": 0.88,
  "legal-document": 0.92,
  "financial-model": 0.80,
  "protocol-design": 0.82,
  "field-notes": 0.60,
  "prior-work": 0.70,
  "external-reference": 0.50,
};

// ── Memory Consolidation Engine ──────────────────────────────

export class MemoryConsolidationEngine {
  private memory: KnowledgeMemory;
  private actions: ConsolidationAction[] = [];

  constructor(memory: KnowledgeMemory) {
    this.memory = memory;
    this.actions = [];
  }

  /**
   * Run full consolidation pipeline.
   * Returns a report of all findings and actions taken.
   */
  consolidate(options: {
    mergeDuplicates?: boolean;
    fixCrossRefs?: boolean;
    autoCluster?: boolean;
  } = {}): ConsolidationReport {
    const {
      mergeDuplicates = true,
      fixCrossRefs = true,
      autoCluster = true,
    } = options;

    this.actions = [];
    const nodes = this.memory.getAllNodes();

    console.log(`[CONSOLIDATE] Starting consolidation of ${nodes.length} nodes...`);

    // 1. Detect duplicates
    const duplicates = this.detectDuplicates(nodes);
    if (mergeDuplicates && duplicates.length > 0) {
      this.mergeDuplicates(duplicates);
      console.log(`[CONSOLIDATE] Merged ${duplicates.length} duplicate groups`);
    }

    // 2. Verify cross-reference integrity
    const crossRefIntegrity = this.verifyCrossReferences(nodes);
    if (fixCrossRefs) {
      this.fixCrossReferences(crossRefIntegrity, nodes);
    }

    // 3. Detect contradictions
    const contradictions = this.detectContradictions(nodes);
    console.log(`[CONSOLIDATE] Found ${contradictions.length} potential contradictions`);

    // 4. Score source confidence
    const confidenceScores = this.scoreAllConfidence(nodes);

    // 5. Build domain clusters
    const clusters = autoCluster ? this.buildClusters(nodes) : [];
    console.log(`[CONSOLIDATE] Built ${clusters.length} domain clusters`);

    // 6. Extract concepts
    const topConcepts = this.extractConcepts(nodes, 20);

    // 7. Normalize citations
    this.normalizeCitations(nodes);

    // Build stats
    const stats = {
      totalNodes: nodes.length,
      totalEvidence: nodes.reduce((s, n) => s + n.supportingEvidence.length, 0),
      totalCitations: nodes.reduce((s, n) => s + n.citations.length, 0),
      totalCrossRefs: nodes.reduce((s, n) => s + n.crossReferences.length, 0),
    };

    const report: Omit<ConsolidationReport, "reportHash"> = {
      generatedAt: new Date().toISOString(),
      stats,
      clusters,
      duplicates,
      contradictions,
      confidenceScores,
      crossRefIntegrity,
      topConcepts,
      actions: this.actions,
    };

    const reportHash = crypto
      .createHash("sha256")
      .update(JSON.stringify(report))
      .digest("hex");

    console.log(`[CONSOLIDATE] Complete. Report hash: ${reportHash.substring(0, 16)}...`);

    return { ...report, reportHash };
  }

  // ── Duplicate Detection ────────────────────────────────────

  private detectDuplicates(nodes: ResearchMemoryNode[]): DuplicateGroup[] {
    const groups: DuplicateGroup[] = [];
    const visited = new Set<string>();

    for (let i = 0; i < nodes.length; i++) {
      if (visited.has(nodes[i].nodeId)) continue;

      const duplicates: string[] = [];
      let method: DuplicateGroup["method"] = "content-similarity";
      let maxSimilarity = 0;

      for (let j = i + 1; j < nodes.length; j++) {
        if (visited.has(nodes[j].nodeId)) continue;

        // Exact hash match
        if (nodes[i].contentHash === nodes[j].contentHash) {
          duplicates.push(nodes[j].nodeId);
          visited.add(nodes[j].nodeId);
          method = "exact-hash";
          maxSimilarity = 1.0;
          continue;
        }

        // Title similarity
        const titleSim = this.stringSimilarity(
          nodes[i].title.toLowerCase(),
          nodes[j].title.toLowerCase()
        );
        if (titleSim > 0.85) {
          duplicates.push(nodes[j].nodeId);
          visited.add(nodes[j].nodeId);
          method = "title-match";
          maxSimilarity = Math.max(maxSimilarity, titleSim);
          continue;
        }

        // Content similarity (Jaccard on word sets)
        const contentSim = this.jaccardSimilarity(
          this.tokenize(nodes[i].content),
          this.tokenize(nodes[j].content)
        );
        if (contentSim > 0.7) {
          duplicates.push(nodes[j].nodeId);
          visited.add(nodes[j].nodeId);
          method = "content-similarity";
          maxSimilarity = Math.max(maxSimilarity, contentSim);
        }
      }

      if (duplicates.length > 0) {
        groups.push({
          primaryNodeId: nodes[i].nodeId,
          duplicateNodeIds: duplicates,
          similarity: maxSimilarity,
          method,
        });
      }
    }

    return groups;
  }

  private mergeDuplicates(groups: DuplicateGroup[]): void {
    for (const group of groups) {
      const primary = this.memory.getNode(group.primaryNodeId);
      if (!primary) continue;

      for (const dupId of group.duplicateNodeIds) {
        const dup = this.memory.getNode(dupId);
        if (!dup) continue;

        // Merge cross-references
        for (const ref of dup.crossReferences) {
          if (!primary.crossReferences.includes(ref) && ref !== primary.nodeId) {
            primary.crossReferences.push(ref);
          }
        }

        // Merge keywords
        for (const kw of dup.keywords) {
          if (!primary.keywords.includes(kw)) {
            primary.keywords.push(kw);
          }
        }

        // Merge evidence (avoid exact duplicates)
        const existingTexts = new Set(primary.supportingEvidence.map((e) => e.text));
        for (const ev of dup.supportingEvidence) {
          if (!existingTexts.has(ev.text)) {
            primary.supportingEvidence.push(ev);
          }
        }

        // Merge citations (avoid exact duplicates by title)
        const existingCitTitles = new Set(primary.citations.map((c) => c.title.toLowerCase()));
        for (const cit of dup.citations) {
          if (!existingCitTitles.has(cit.title.toLowerCase())) {
            primary.citations.push(cit);
          }
        }

        // Add version history entry
        primary.versionHistory.push({
          version: (parseFloat(primary.versionHistory[primary.versionHistory.length - 1]?.version || "1.0") + 0.1).toFixed(1),
          timestamp: new Date().toISOString(),
          action: "amended",
          description: `Merged duplicate node ${dupId} (method: ${group.method}, similarity: ${group.similarity.toFixed(2)})`,
          contentHash: primary.contentHash,
        });

        // Delete the duplicate
        this.memory.deleteNode(dupId);

        this.actions.push({
          type: "merged-duplicate",
          description: `Merged node ${dupId} into ${group.primaryNodeId} (${group.method}, similarity: ${group.similarity.toFixed(2)})`,
          affectedNodeIds: [group.primaryNodeId, dupId],
          timestamp: new Date().toISOString(),
        });
      }

      // Save the primary node updates
      this.memory.updateNode(primary.nodeId, {
        keywords: primary.keywords,
      });
    }
  }

  // ── Cross-Reference Integrity ──────────────────────────────

  private verifyCrossReferences(nodes: ResearchMemoryNode[]): CrossRefIntegrity {
    const nodeIds = new Set(nodes.map((n) => n.nodeId));
    let totalRefs = 0;
    let validRefs = 0;
    const brokenRefs: string[] = [];
    const orphanNodes: string[] = [];
    const bidirectionalMissing: Array<{ from: string; to: string }> = [];

    // Track incoming references
    const incomingRefs = new Set<string>();

    for (const node of nodes) {
      totalRefs += node.crossReferences.length;

      for (const ref of node.crossReferences) {
        if (nodeIds.has(ref)) {
          validRefs++;
          incomingRefs.add(ref);

          // Check bidirectional consistency
          const targetNode = nodes.find((n) => n.nodeId === ref);
          if (targetNode && !targetNode.crossReferences.includes(node.nodeId)) {
            bidirectionalMissing.push({ from: node.nodeId, to: ref });
          }
        } else {
          brokenRefs.push(`${node.nodeId} → ${ref}`);
        }
      }
    }

    // Find orphans (no incoming or outgoing refs)
    for (const node of nodes) {
      if (node.crossReferences.length === 0 && !incomingRefs.has(node.nodeId)) {
        orphanNodes.push(node.nodeId);
      }
    }

    return { totalRefs, validRefs, brokenRefs, orphanNodes, bidirectionalMissing };
  }

  private fixCrossReferences(integrity: CrossRefIntegrity, nodes: ResearchMemoryNode[]): void {
    // Fix bidirectional missing
    for (const missing of integrity.bidirectionalMissing) {
      const targetNode = nodes.find((n) => n.nodeId === missing.to);
      if (targetNode && !targetNode.crossReferences.includes(missing.from)) {
        targetNode.crossReferences.push(missing.from);
        this.actions.push({
          type: "added-cross-ref",
          description: `Added bidirectional cross-reference: ${missing.to} → ${missing.from}`,
          affectedNodeIds: [missing.from, missing.to],
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Remove broken references
    for (const node of nodes) {
      const nodeIds = new Set(nodes.map((n) => n.nodeId));
      const before = node.crossReferences.length;
      node.crossReferences = node.crossReferences.filter((ref) => nodeIds.has(ref));
      if (node.crossReferences.length < before) {
        this.actions.push({
          type: "fixed-cross-ref",
          description: `Removed ${before - node.crossReferences.length} broken cross-references from ${node.nodeId}`,
          affectedNodeIds: [node.nodeId],
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  // ── Contradiction Detection ────────────────────────────────

  private detectContradictions(nodes: ResearchMemoryNode[]): Contradiction[] {
    const contradictions: Contradiction[] = [];

    // Extract all numeric claims for comparison
    const numericClaims: Array<{
      nodeId: string;
      fragment: EvidenceFragment;
      numbers: Array<{ value: number; context: string }>;
    }> = [];

    for (const node of nodes) {
      for (const ev of node.supportingEvidence) {
        const numbers = this.extractNumbers(ev.text);
        if (numbers.length > 0) {
          numericClaims.push({ nodeId: node.nodeId, fragment: ev, numbers });
        }
      }
    }

    // Compare numeric claims across different nodes
    for (let i = 0; i < numericClaims.length; i++) {
      for (let j = i + 1; j < numericClaims.length; j++) {
        if (numericClaims[i].nodeId === numericClaims[j].nodeId) continue;

        // Check if claims are about similar topics but have different numbers
        const topicSim = this.jaccardSimilarity(
          this.tokenize(numericClaims[i].fragment.text),
          this.tokenize(numericClaims[j].fragment.text)
        );

        if (topicSim > 0.3) {
          // Similar topic — check if numbers differ significantly
          for (const numA of numericClaims[i].numbers) {
            for (const numB of numericClaims[j].numbers) {
              const ratio = numA.value / numB.value;
              if (ratio > 2 || ratio < 0.5) {
                contradictions.push({
                  evidenceA: {
                    nodeId: numericClaims[i].nodeId,
                    fragmentId: numericClaims[i].fragment.fragmentId,
                    text: numericClaims[i].fragment.text.substring(0, 200),
                  },
                  evidenceB: {
                    nodeId: numericClaims[j].nodeId,
                    fragmentId: numericClaims[j].fragment.fragmentId,
                    text: numericClaims[j].fragment.text.substring(0, 200),
                  },
                  type: "statistical",
                  description: `Numeric discrepancy: ${numA.value} vs ${numB.value} (ratio: ${ratio.toFixed(2)})`,
                  severity: Math.min(1, Math.abs(Math.log10(ratio)) / 2),
                });
              }
            }
          }
        }
      }
    }

    // Flag contradictions
    for (const c of contradictions) {
      this.actions.push({
        type: "flagged-contradiction",
        description: `${c.type} contradiction: ${c.description}`,
        affectedNodeIds: [c.evidenceA.nodeId, c.evidenceB.nodeId],
        timestamp: new Date().toISOString(),
      });
    }

    return contradictions;
  }

  // ── Source Confidence Scoring ──────────────────────────────

  private scoreAllConfidence(nodes: ResearchMemoryNode[]): SourceConfidence[] {
    return nodes.map((node) => this.scoreConfidence(node, nodes));
  }

  private scoreConfidence(
    node: ResearchMemoryNode,
    allNodes: ResearchMemoryNode[]
  ): SourceConfidence {
    // Citation presence (0-20)
    const citationPresence = Math.min(20, node.citations.length * 4);

    // Cross-reference count (0-20)
    const incomingRefs = allNodes.filter((n) =>
      n.crossReferences.includes(node.nodeId)
    ).length;
    const crossReferenceCount = Math.min(
      20,
      (node.crossReferences.length + incomingRefs) * 3
    );

    // Evidence quality (0-25)
    const avgConfidence =
      node.supportingEvidence.length > 0
        ? node.supportingEvidence.reduce((s, e) => s + e.confidence, 0) /
          node.supportingEvidence.length
        : 0;
    const evidenceQuality = Math.round(avgConfidence * 25);

    // Content depth (0-15)
    const wordCount = node.content.split(/\s+/).length;
    const contentDepth = Math.min(15, Math.round((wordCount / 1000) * 5));

    // Recency bonus (0-10)
    const daysSinceIngestion =
      (Date.now() - new Date(node.ingestedAt).getTime()) / (1000 * 60 * 60 * 24);
    const recency = Math.max(0, Math.round(10 - daysSinceIngestion * 0.1));

    // Source type weight (0-10)
    const sourceTypeWeight = Math.round(
      (SOURCE_TYPE_WEIGHTS[node.sourceType] || 0.5) * 10
    );

    const score =
      citationPresence +
      crossReferenceCount +
      evidenceQuality +
      contentDepth +
      recency +
      sourceTypeWeight;

    this.actions.push({
      type: "scored-confidence",
      description: `Confidence score for "${node.title}": ${score}/100`,
      affectedNodeIds: [node.nodeId],
      timestamp: new Date().toISOString(),
    });

    return {
      nodeId: node.nodeId,
      title: node.title,
      score: Math.min(100, score),
      factors: {
        citationPresence,
        crossReferenceCount,
        evidenceQuality,
        contentDepth,
        recency,
        sourceTypeWeight,
      },
    };
  }

  // ── Domain Clustering ──────────────────────────────────────

  private buildClusters(nodes: ResearchMemoryNode[]): DomainCluster[] {
    // Group by topic first
    const topicGroups: Record<string, ResearchMemoryNode[]> = {};
    for (const node of nodes) {
      const topic = node.topic.toLowerCase().trim();
      if (!topicGroups[topic]) topicGroups[topic] = [];
      topicGroups[topic].push(node);
    }

    // Merge similar topics
    const mergedTopics = this.mergeRelatedTopics(topicGroups);

    // Build clusters
    const clusters: DomainCluster[] = [];
    for (const [domain, groupNodes] of Object.entries(mergedTopics)) {
      const allKeywords = new Set<string>();
      let totalEvidence = 0;
      let totalCitations = 0;
      let totalConfidence = 0;

      for (const node of groupNodes) {
        node.keywords.forEach((k) => allKeywords.add(k.toLowerCase()));
        totalEvidence += node.supportingEvidence.length;
        totalCitations += node.citations.length;
        totalConfidence +=
          node.supportingEvidence.length > 0
            ? node.supportingEvidence.reduce((s, e) => s + e.confidence, 0) /
              node.supportingEvidence.length
            : 0.5;
      }

      // Coherence: how much keyword overlap exists between nodes
      const coherence = this.computeClusterCoherence(groupNodes);

      clusters.push({
        clusterId: crypto
          .createHash("sha256")
          .update(domain)
          .digest("hex")
          .substring(0, 12),
        domain,
        keywords: Array.from(allKeywords).slice(0, 20),
        nodeIds: groupNodes.map((n) => n.nodeId),
        nodeCount: groupNodes.length,
        totalEvidence,
        totalCitations,
        confidence: groupNodes.length > 0 ? totalConfidence / groupNodes.length : 0,
        coherence,
      });
    }

    // Sort by node count descending
    clusters.sort((a, b) => b.nodeCount - a.nodeCount);

    return clusters;
  }

  private mergeRelatedTopics(
    groups: Record<string, ResearchMemoryNode[]>
  ): Record<string, ResearchMemoryNode[]> {
    const topics = Object.keys(groups);
    const merged: Record<string, ResearchMemoryNode[]> = {};
    const visited = new Set<string>();

    for (const topic of topics) {
      if (visited.has(topic)) continue;
      visited.add(topic);

      const mergedNodes = [...groups[topic]];
      let mergedDomain = topic;

      for (const otherTopic of topics) {
        if (visited.has(otherTopic)) continue;

        const sim = this.jaccardSimilarity(
          this.tokenize(topic),
          this.tokenize(otherTopic)
        );

        if (sim > 0.4) {
          mergedNodes.push(...groups[otherTopic]);
          visited.add(otherTopic);
          // Use the longer topic name as domain
          if (otherTopic.length > mergedDomain.length) {
            mergedDomain = otherTopic;
          }
        }
      }

      merged[mergedDomain] = mergedNodes;
    }

    return merged;
  }

  private computeClusterCoherence(nodes: ResearchMemoryNode[]): number {
    if (nodes.length <= 1) return 1.0;

    let totalSim = 0;
    let comparisons = 0;

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        totalSim += this.jaccardSimilarity(
          new Set(nodes[i].keywords.map((k) => k.toLowerCase())),
          new Set(nodes[j].keywords.map((k) => k.toLowerCase()))
        );
        comparisons++;
      }
    }

    return comparisons > 0 ? totalSim / comparisons : 0;
  }

  // ── Concept Extraction ─────────────────────────────────────

  private extractConcepts(
    nodes: ResearchMemoryNode[],
    limit: number
  ): ConceptFrequency[] {
    const conceptMap: Map<
      string,
      { frequency: number; nodeIds: Set<string>; evidenceCount: number }
    > = new Map();

    // Stopwords to filter out
    const stopwords = new Set([
      "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
      "have", "has", "had", "do", "does", "did", "will", "would", "shall",
      "should", "may", "might", "must", "can", "could", "and", "but", "or",
      "nor", "not", "so", "yet", "both", "either", "neither", "each", "every",
      "all", "any", "few", "more", "most", "other", "some", "such", "no",
      "only", "same", "than", "too", "very", "just", "because", "as", "until",
      "while", "of", "at", "by", "for", "with", "about", "against", "between",
      "through", "during", "before", "after", "above", "below", "to", "from",
      "up", "down", "in", "out", "on", "off", "over", "under", "again",
      "further", "then", "once", "here", "there", "when", "where", "why",
      "how", "this", "that", "these", "those", "it", "its", "they", "them",
      "their", "we", "us", "our", "he", "him", "his", "she", "her",
    ]);

    for (const node of nodes) {
      // Keywords are already curated concepts
      for (const kw of node.keywords) {
        const normalized = kw.toLowerCase().trim();
        if (normalized.length < 3 || stopwords.has(normalized)) continue;

        if (!conceptMap.has(normalized)) {
          conceptMap.set(normalized, {
            frequency: 0,
            nodeIds: new Set(),
            evidenceCount: 0,
          });
        }
        const entry = conceptMap.get(normalized)!;
        entry.frequency++;
        entry.nodeIds.add(node.nodeId);
      }

      // Also extract from evidence tags
      for (const ev of node.supportingEvidence) {
        for (const tag of ev.tags) {
          const normalized = tag.toLowerCase().trim();
          if (normalized.length < 3 || stopwords.has(normalized)) continue;

          if (!conceptMap.has(normalized)) {
            conceptMap.set(normalized, {
              frequency: 0,
              nodeIds: new Set(),
              evidenceCount: 0,
            });
          }
          const entry = conceptMap.get(normalized)!;
          entry.frequency++;
          entry.nodeIds.add(node.nodeId);
          entry.evidenceCount++;
        }
      }
    }

    // Convert and sort
    const concepts: ConceptFrequency[] = Array.from(conceptMap.entries())
      .map(([concept, data]) => ({
        concept,
        frequency: data.frequency,
        nodeIds: Array.from(data.nodeIds),
        evidenceCount: data.evidenceCount,
      }))
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, limit);

    return concepts;
  }

  // ── Citation Normalization ─────────────────────────────────

  private normalizeCitations(nodes: ResearchMemoryNode[]): void {
    for (const node of nodes) {
      let normalized = false;

      for (const cit of node.citations) {
        // Trim whitespace from all string fields
        if (cit.title !== cit.title.trim()) {
          cit.title = cit.title.trim();
          normalized = true;
        }
        for (let i = 0; i < cit.authors.length; i++) {
          if (cit.authors[i] !== cit.authors[i].trim()) {
            cit.authors[i] = cit.authors[i].trim();
            normalized = true;
          }
        }
        if (cit.source !== cit.source.trim()) {
          cit.source = cit.source.trim();
          normalized = true;
        }
      }

      if (normalized) {
        this.actions.push({
          type: "normalized-citation",
          description: `Normalized citations in node ${node.nodeId}`,
          affectedNodeIds: [node.nodeId],
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  // ── Utility Methods ────────────────────────────────────────

  private tokenize(text: string): Set<string> {
    return new Set(
      text
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, "")
        .split(/\s+/)
        .filter((w) => w.length > 2)
    );
  }

  private jaccardSimilarity(setA: Set<string>, setB: Set<string>): number {
    const intersection = new Set([...setA].filter((x) => setB.has(x)));
    const union = new Set([...setA, ...setB]);
    return union.size > 0 ? intersection.size / union.size : 0;
  }

  private stringSimilarity(a: string, b: string): number {
    if (a === b) return 1;
    if (a.length === 0 || b.length === 0) return 0;

    // Simple Levenshtein-based similarity
    const maxLen = Math.max(a.length, b.length);
    const distance = this.levenshtein(a, b);
    return 1 - distance / maxLen;
  }

  private levenshtein(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        const cost = b.charAt(i - 1) === a.charAt(j - 1) ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }
    return matrix[b.length][a.length];
  }

  private extractNumbers(text: string): Array<{ value: number; context: string }> {
    const results: Array<{ value: number; context: string }> = [];
    const regex = /\b(\d+(?:,\d{3})*(?:\.\d+)?)\s*(%|percent|million|billion|trillion|thousand)?\b/gi;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      let value = parseFloat(match[1].replace(/,/g, ""));
      const modifier = match[2]?.toLowerCase();

      if (modifier === "thousand") value *= 1000;
      if (modifier === "million") value *= 1e6;
      if (modifier === "billion") value *= 1e9;
      if (modifier === "trillion") value *= 1e12;

      // Get surrounding context
      const start = Math.max(0, match.index - 30);
      const end = Math.min(text.length, match.index + match[0].length + 30);
      const context = text.substring(start, end).trim();

      results.push({ value, context });
    }

    return results;
  }
}
