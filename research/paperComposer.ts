// ─────────────────────────────────────────────────────────────
// Paper Composer Engine — Structured Document Generation
//
// Composes three paper formats from knowledge memory:
//   1. Academic Paper  (Abstract → Conclusion)
//   2. Technical Whitepaper (Executive Summary → Legal)
//   3. Regulatory Submission (Compliance → Exhibits)
//
// Each paper builds on persistent knowledge state.
// Output: ComposedPaper → can be exported via existing pipeline.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import {
  ComposedPaper,
  PaperFormat,
  AcademicStructure,
  WhitepaperStructure,
  RegulatoryStructure,
  CitationStyle,
  Citation,
  AppendixEntry,
  ResearchMemoryNode,
} from "../schema/researchSchema";
import { DocumentObject, Section } from "../schema/documentSchema";

// ── Composer ─────────────────────────────────────────────────

export interface ComposeOptions {
  title: string;
  authors: string[];
  format: PaperFormat;
  citationStyle?: CitationStyle;
  /** Knowledge memory nodes to draw from */
  sourceNodes?: ResearchMemoryNode[];
  /** Raw section overrides */
  sections?: Record<string, string>;
  /** Additional citations */
  additionalCitations?: Citation[];
}

/**
 * Compose a paper from knowledge memory nodes and user-provided overrides.
 */
export function composePaper(options: ComposeOptions): ComposedPaper {
  const {
    title,
    authors,
    format,
    citationStyle = "apa",
    sourceNodes = [],
    sections = {},
    additionalCitations = [],
  } = options;

  // Gather all citations from source nodes + additional
  const allCitations = collectCitations(sourceNodes, additionalCitations);

  // Build structure based on format
  let structure: AcademicStructure | WhitepaperStructure | RegulatoryStructure;

  switch (format) {
    case "academic":
      structure = composeAcademic(sourceNodes, sections, allCitations);
      break;
    case "whitepaper":
      structure = composeWhitepaper(sourceNodes, sections, allCitations);
      break;
    case "regulatory":
      structure = composeRegulatory(sourceNodes, sections, allCitations);
      break;
    default:
      structure = composeAcademic(sourceNodes, sections, allCitations);
  }

  const paperId = crypto.createHash("sha256")
    .update(title + authors.join(",") + Date.now().toString())
    .digest("hex")
    .substring(0, 16);

  const content = JSON.stringify(structure);
  const contentHash = crypto.createHash("sha256").update(content).digest("hex");

  const paper: ComposedPaper = {
    paperId,
    format,
    title,
    authors,
    date: new Date().toISOString(),
    citationStyle,
    structure,
    sourceNodes: sourceNodes.map((n) => n.nodeId),
    contentHash,
    wordCount: computeWordCount(structure),
  };

  return paper;
}

/**
 * Convert a ComposedPaper into a DocumentObject for export through
 * the existing HTML/PDF/DOCX pipeline.
 */
export function paperToDocumentObject(paper: ComposedPaper): DocumentObject {
  const sections: Section[] = [];
  let sectionIndex = 0;

  const makeSection = (
    type: "header" | "subheader" | "paragraph",
    label: string,
    content: string,
    depth: number = 0
  ): Section => ({
    id: `paper-section-${sectionIndex++}`,
    type,
    depth,
    label,
    content,
    children: [],
    style: {},
  });

  // Title section
  sections.push(makeSection("header", paper.title, paper.title));

  // Authors + Date
  sections.push(makeSection("paragraph", "Authors", `${paper.authors.join(", ")} — ${paper.date}`));
  sections.push(makeSection("divider" as any, "", ""));

  // Build sections based on format
  if (paper.format === "academic") {
    const s = paper.structure as AcademicStructure;
    if (s.abstract) sections.push(makeSection("subheader", "Abstract", ""), makeSection("paragraph", "", s.abstract, 1));
    if (s.keywords.length) sections.push(makeSection("paragraph", "Keywords", s.keywords.join(", "), 1));
    if (s.introduction) sections.push(makeSection("subheader", "1. Introduction", ""), makeSection("paragraph", "", s.introduction, 1));
    if (s.literatureReview) sections.push(makeSection("subheader", "2. Literature Review", ""), makeSection("paragraph", "", s.literatureReview, 1));
    if (s.methodology) sections.push(makeSection("subheader", "3. Methodology", ""), makeSection("paragraph", "", s.methodology, 1));
    if (s.results) sections.push(makeSection("subheader", "4. Results", ""), makeSection("paragraph", "", s.results, 1));
    if (s.discussion) sections.push(makeSection("subheader", "5. Discussion", ""), makeSection("paragraph", "", s.discussion, 1));
    if (s.limitations) sections.push(makeSection("subheader", "6. Limitations", ""), makeSection("paragraph", "", s.limitations, 1));
    if (s.conclusion) sections.push(makeSection("subheader", "7. Conclusion", ""), makeSection("paragraph", "", s.conclusion, 1));
    if (s.acknowledgments) sections.push(makeSection("subheader", "Acknowledgments", ""), makeSection("paragraph", "", s.acknowledgments, 1));
  } else if (paper.format === "whitepaper") {
    const s = paper.structure as WhitepaperStructure;
    if (s.executiveSummary) sections.push(makeSection("subheader", "Executive Summary", ""), makeSection("paragraph", "", s.executiveSummary, 1));
    if (s.problemStatement) sections.push(makeSection("subheader", "Problem Statement", ""), makeSection("paragraph", "", s.problemStatement, 1));
    if (s.architecture) sections.push(makeSection("subheader", "Architecture", ""), makeSection("paragraph", "", s.architecture, 1));
    if (s.protocolDesign) sections.push(makeSection("subheader", "Protocol Design", ""), makeSection("paragraph", "", s.protocolDesign, 1));
    if (s.securityModel) sections.push(makeSection("subheader", "Security Model", ""), makeSection("paragraph", "", s.securityModel, 1));
    if (s.economicModel) sections.push(makeSection("subheader", "Economic Model", ""), makeSection("paragraph", "", s.economicModel, 1));
    if (s.governanceModel) sections.push(makeSection("subheader", "Governance Model", ""), makeSection("paragraph", "", s.governanceModel, 1));
    if (s.riskFactors) sections.push(makeSection("subheader", "Risk Factors", ""), makeSection("paragraph", "", s.riskFactors, 1));
    if (s.roadmap) sections.push(makeSection("subheader", "Roadmap", ""), makeSection("paragraph", "", s.roadmap, 1));
    if (s.legalConsiderations) sections.push(makeSection("subheader", "Legal Considerations", ""), makeSection("paragraph", "", s.legalConsiderations, 1));
  } else if (paper.format === "regulatory") {
    const s = paper.structure as RegulatoryStructure;
    if (s.complianceSummary) sections.push(makeSection("subheader", "Compliance Summary", ""), makeSection("paragraph", "", s.complianceSummary, 1));
    if (s.riskDisclosures) sections.push(makeSection("subheader", "Risk Disclosures", ""), makeSection("paragraph", "", s.riskDisclosures, 1));
    if (s.financialMechanics) sections.push(makeSection("subheader", "Financial Mechanics", ""), makeSection("paragraph", "", s.financialMechanics, 1));
    if (s.legalFramework) sections.push(makeSection("subheader", "Legal Framework", ""), makeSection("paragraph", "", s.legalFramework, 1));
    if (s.controlProcedures) sections.push(makeSection("subheader", "Control Procedures", ""), makeSection("paragraph", "", s.controlProcedures, 1));
    if (s.auditMethodology) sections.push(makeSection("subheader", "Audit Methodology", ""), makeSection("paragraph", "", s.auditMethodology, 1));
    if (s.filingDetails) {
      const fd = s.filingDetails;
      sections.push(
        makeSection("subheader", "Filing Details", ""),
        makeSection("paragraph", "", `Type: ${fd.filingType} | Jurisdiction: ${fd.jurisdiction} | Regulatory Body: ${fd.regulatoryBody} | Filing Date: ${fd.filingDate}`, 1)
      );
    }
  }

  // References section
  const structure = paper.structure;
  const refs = "references" in structure ? structure.references : [];
  if (refs.length > 0) {
    sections.push(makeSection("subheader", "References", ""));
    for (let i = 0; i < refs.length; i++) {
      const c = refs[i];
      sections.push(
        makeSection("numbered-item" as any, `[${i + 1}]`, `${c.authors.join(", ")} (${c.year}). ${c.title}. ${c.source}.`, 1)
      );
    }
  }

  // Appendices
  const appendices: AppendixEntry[] = "appendices" in structure ? (structure as any).appendices : [];
  for (const app of appendices) {
    sections.push(
      makeSection("subheader", `Appendix ${app.label}: ${app.title}`, ""),
      makeSection("paragraph", "", app.content, 1)
    );
  }

  // Word count footer
  sections.push(makeSection("divider" as any, "", ""));
  sections.push(makeSection("footer" as any, "Word Count", `Total: ${paper.wordCount.total} words`));

  return {
    metadata: {
      title: paper.title,
      type: "txt",
      pageCount: Math.ceil(paper.wordCount.total / 250),
      sourceFile: `composed-${paper.paperId}`,
      ingestedAt: paper.date,
      language: "en",
    },
    structure: sections,
    styles: {
      primaryFont: "Georgia, 'Times New Roman', serif",
      secondaryFont: "Arial, Helvetica, sans-serif",
      headingSize: "24px",
      bodySize: "12px",
      primaryColor: "#1a1a2e",
      secondaryColor: "#16213e",
      accentColor: "#0f3460",
      backgroundColor: "#ffffff",
      lineHeight: "1.8",
    },
    components: [],
    semanticTags: ["research", paper.format, `citations-${paper.citationStyle}`],
  };
}

// ── Format-specific Composers ────────────────────────────────

function composeAcademic(
  nodes: ResearchMemoryNode[],
  overrides: Record<string, string>,
  citations: Citation[]
): AcademicStructure {
  // Synthesize from knowledge nodes
  const allContent = nodes.map((n) => n.content).join("\n\n");
  const allEvidence = nodes.flatMap((n) => n.supportingEvidence);
  const allKeywords = [...new Set(nodes.flatMap((n) => n.keywords))];

  return {
    abstract: overrides.abstract || synthesizeSection(allContent, "abstract", 250),
    keywords: allKeywords.slice(0, 10),
    introduction: overrides.introduction || synthesizeSection(allContent, "introduction", 500),
    literatureReview: overrides.literatureReview || synthesizeSection(allContent, "literature review", 800),
    methodology: overrides.methodology || synthesizeSection(allContent, "methodology", 600),
    results: overrides.results || synthesizeSection(allContent, "results", 600),
    discussion: overrides.discussion || synthesizeSection(allContent, "discussion", 600),
    limitations: overrides.limitations || synthesizeSection(allContent, "limitations", 300),
    conclusion: overrides.conclusion || synthesizeSection(allContent, "conclusion", 400),
    references: citations,
    appendices: buildAppendices(nodes),
    acknowledgments: overrides.acknowledgments || "",
  };
}

function composeWhitepaper(
  nodes: ResearchMemoryNode[],
  overrides: Record<string, string>,
  citations: Citation[]
): WhitepaperStructure {
  const allContent = nodes.map((n) => n.content).join("\n\n");

  return {
    executiveSummary: overrides.executiveSummary || synthesizeSection(allContent, "executive summary", 400),
    problemStatement: overrides.problemStatement || synthesizeSection(allContent, "problem", 500),
    architecture: overrides.architecture || synthesizeSection(allContent, "architecture", 800),
    protocolDesign: overrides.protocolDesign || synthesizeSection(allContent, "protocol design", 800),
    securityModel: overrides.securityModel || synthesizeSection(allContent, "security", 600),
    economicModel: overrides.economicModel || synthesizeSection(allContent, "economic model", 600),
    governanceModel: overrides.governanceModel || synthesizeSection(allContent, "governance", 500),
    riskFactors: overrides.riskFactors || synthesizeSection(allContent, "risk", 400),
    roadmap: overrides.roadmap || synthesizeSection(allContent, "roadmap", 300),
    legalConsiderations: overrides.legalConsiderations || synthesizeSection(allContent, "legal", 400),
    references: citations,
    appendices: buildAppendices(nodes),
  };
}

function composeRegulatory(
  nodes: ResearchMemoryNode[],
  overrides: Record<string, string>,
  citations: Citation[]
): RegulatoryStructure {
  const allContent = nodes.map((n) => n.content).join("\n\n");

  return {
    complianceSummary: overrides.complianceSummary || synthesizeSection(allContent, "compliance", 500),
    riskDisclosures: overrides.riskDisclosures || synthesizeSection(allContent, "risk disclosure", 600),
    financialMechanics: overrides.financialMechanics || synthesizeSection(allContent, "financial mechanics", 600),
    legalFramework: overrides.legalFramework || synthesizeSection(allContent, "legal framework", 500),
    controlProcedures: overrides.controlProcedures || synthesizeSection(allContent, "control procedures", 400),
    auditMethodology: overrides.auditMethodology || synthesizeSection(allContent, "audit methodology", 400),
    filingDetails: {
      filingType: overrides.filingType || "General Submission",
      jurisdiction: overrides.jurisdiction || "US",
      regulatoryBody: overrides.regulatoryBody || "SEC",
      filingDate: new Date().toISOString().split("T")[0],
      effectiveDate: overrides.effectiveDate,
      registrationNumber: overrides.registrationNumber,
    },
    references: citations,
    appendices: buildAppendices(nodes),
    exhibits: [],
  };
}

// ── Synthesis Helpers ────────────────────────────────────────

/**
 * Synthesize a section from content by finding relevant passages.
 * This uses keyword extraction to pull the most relevant paragraphs
 * for a given section topic.
 */
function synthesizeSection(content: string, sectionTopic: string, maxWords: number): string {
  if (!content || content.length === 0) {
    return `[${sectionTopic.toUpperCase()}: Content to be provided. This section covers the ${sectionTopic} aspects of the research.]`;
  }

  const paragraphs = content
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter((p) => p.length > 50);

  if (paragraphs.length === 0) {
    return `[${sectionTopic.toUpperCase()}: Synthesis from source material pending.]`;
  }

  // Score paragraphs by topic relevance
  const topicTerms = sectionTopic.toLowerCase().split(/\s+/);
  const scored: { text: string; score: number }[] = [];

  for (const para of paragraphs) {
    const lower = para.toLowerCase();
    let score = 0;
    for (const term of topicTerms) {
      const matches = (lower.match(new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length;
      score += matches * 3;
    }
    // Bonus for length (meatier paragraphs)
    score += Math.min(para.length / 100, 5);
    scored.push({ text: para, score });
  }

  scored.sort((a, b) => b.score - a.score);

  // Take top scored paragraphs up to word limit
  let result = "";
  let wordCount = 0;

  for (const { text } of scored) {
    const words = text.split(/\s+/).length;
    if (wordCount + words > maxWords) {
      if (wordCount === 0) {
        // Take at least something even if over limit
        result = text.split(/\s+/).slice(0, maxWords).join(" ") + "...";
      }
      break;
    }
    result += (result ? "\n\n" : "") + text;
    wordCount += words;
  }

  return result || `[${sectionTopic.toUpperCase()}: Content synthesis pending.]`;
}

/** Collect and deduplicate citations */
function collectCitations(nodes: ResearchMemoryNode[], additional: Citation[]): Citation[] {
  const seen = new Set<string>();
  const all: Citation[] = [];

  for (const node of nodes) {
    for (const c of node.citations) {
      if (!seen.has(c.citationId)) {
        seen.add(c.citationId);
        all.push(c);
      }
    }
  }

  for (const c of additional) {
    if (!seen.has(c.citationId)) {
      seen.add(c.citationId);
      all.push(c);
    }
  }

  return all;
}

/** Build appendices from source nodes (each node summary becomes an appendix) */
function buildAppendices(nodes: ResearchMemoryNode[]): AppendixEntry[] {
  return nodes
    .filter((n) => n.summary && n.summary !== "No summary available.")
    .map((n, i) => ({
      label: String.fromCharCode(65 + i), // A, B, C...
      title: `Source: ${n.title}`,
      content: `Source Type: ${n.sourceType}\nTopic: ${n.topic}\nIngested: ${n.ingestedAt}\n\n${n.summary}`,
    }));
}

/** Compute word counts for a paper structure */
function computeWordCount(structure: AcademicStructure | WhitepaperStructure | RegulatoryStructure): { total: number; bySections: Record<string, number> } {
  const bySections: Record<string, number> = {};
  let total = 0;

  const countWords = (text: string): number => text.split(/\s+/).filter(Boolean).length;

  for (const [key, value] of Object.entries(structure)) {
    if (typeof value === "string") {
      const wc = countWords(value);
      bySections[key] = wc;
      total += wc;
    } else if (Array.isArray(value)) {
      // citations, appendices, etc.
      let sectionTotal = 0;
      for (const item of value) {
        if (typeof item === "object" && item !== null) {
          for (const v of Object.values(item)) {
            if (typeof v === "string") sectionTotal += countWords(v);
          }
        }
      }
      bySections[key] = sectionTotal;
      total += sectionTotal;
    }
  }

  return { total, bySections };
}
