// ─────────────────────────────────────────────────────────────
// Research & Publication Schema — Knowledge Production Layer
//
// Types for:
//   • Knowledge memory nodes (prior research, frameworks)
//   • Paper composition (academic, whitepaper, regulatory)
//   • Citation formatting (APA, MLA, Chicago, IEEE, Bluebook)
//   • Peer review simulation (academic, legal, technical, economic)
//   • Agreement state machine (Draft → Active → Completed)
// ─────────────────────────────────────────────────────────────

// ── Knowledge Memory ─────────────────────────────────────────

/** A single node in the knowledge memory graph */
export interface ResearchMemoryNode {
  /** Unique node ID */
  nodeId: string;
  /** Human-readable title */
  title: string;
  /** Source classification */
  sourceType: KnowledgeSourceType;
  /** Topic area */
  topic: string;
  /** Sub-topics / keywords */
  keywords: string[];
  /** Full extracted text content */
  content: string;
  /** Structured summary (auto-generated) */
  summary: string;
  /** Supporting evidence pulled from source */
  supportingEvidence: EvidenceFragment[];
  /** Citations referenced in this node */
  citations: Citation[];
  /** Cross-references to other memory nodes */
  crossReferences: string[];   // nodeIds
  /** Source file path or URL */
  sourceFile: string;
  /** SHA-256 of the source content */
  contentHash: string;
  /** CID if pushed to IPFS */
  cid?: string;
  /** SKU if assigned */
  sku?: string;
  /** Ingestion timestamp */
  ingestedAt: string;
  /** Last accessed timestamp */
  lastAccessed: string;
  /** Version lineage — tracks amendments/updates */
  versionHistory: VersionEntry[];
  /** Metadata bag */
  metadata: Record<string, string>;
}

/** Source type classification */
export type KnowledgeSourceType =
  | "research-paper"
  | "whitepaper"
  | "regulatory-filing"
  | "technical-spec"
  | "legal-document"
  | "financial-model"
  | "protocol-design"
  | "field-notes"
  | "prior-work"
  | "external-reference";

/** A fragment of evidence extracted from a source */
export interface EvidenceFragment {
  fragmentId: string;
  text: string;
  pageNumber?: number;
  sectionReference?: string;
  confidence: number;        // 0-1 score
  tags: string[];
}

/** Version entry for knowledge lineage */
export interface VersionEntry {
  version: string;
  timestamp: string;
  action: "created" | "updated" | "amended" | "superseded";
  description: string;
  contentHash: string;
  cid?: string;
}

// ── Citations ────────────────────────────────────────────────

/** Supported citation format styles */
export type CitationStyle =
  | "apa"
  | "mla"
  | "chicago"
  | "ieee"
  | "bluebook"
  | "sec-filing"
  | "arxiv"
  | "grant"
  | "board-memo";

/** A structured citation record */
export interface Citation {
  citationId: string;
  type: CitationType;
  authors: string[];
  title: string;
  year: number;
  /** Publication / journal / conference name */
  source: string;
  /** Volume, issue, page numbers */
  volume?: string;
  issue?: string;
  pages?: string;
  /** DOI, URL, ISBN */
  doi?: string;
  url?: string;
  isbn?: string;
  /** Publisher information */
  publisher?: string;
  location?: string;
  /** Access date (for web sources) */
  accessDate?: string;
  /** Edition number */
  edition?: string;
  /** Additional notes */
  notes?: string;
}

/** Citation source types */
export type CitationType =
  | "journal-article"
  | "book"
  | "book-chapter"
  | "conference-paper"
  | "thesis"
  | "report"
  | "website"
  | "patent"
  | "legal-case"
  | "statute"
  | "regulatory-filing"
  | "preprint"
  | "working-paper"
  | "personal-communication";

// ── Paper Composition ────────────────────────────────────────

/** Paper format types */
export type PaperFormat =
  | "academic"
  | "whitepaper"
  | "regulatory";

/** Academic paper structure */
export interface AcademicStructure {
  abstract: string;
  keywords: string[];
  introduction: string;
  literatureReview: string;
  methodology: string;
  results: string;
  discussion: string;
  limitations: string;
  conclusion: string;
  references: Citation[];
  appendices: AppendixEntry[];
  acknowledgments?: string;
}

/** Whitepaper structure */
export interface WhitepaperStructure {
  executiveSummary: string;
  problemStatement: string;
  architecture: string;
  protocolDesign: string;
  securityModel: string;
  economicModel: string;
  governanceModel: string;
  riskFactors: string;
  roadmap: string;
  legalConsiderations: string;
  references: Citation[];
  appendices: AppendixEntry[];
}

/** Regulatory submission structure */
export interface RegulatoryStructure {
  complianceSummary: string;
  riskDisclosures: string;
  financialMechanics: string;
  legalFramework: string;
  controlProcedures: string;
  auditMethodology: string;
  filingDetails: FilingDetails;
  references: Citation[];
  appendices: AppendixEntry[];
  exhibits: ExhibitEntry[];
}

/** Filing details for regulatory submissions */
export interface FilingDetails {
  filingType: string;
  jurisdiction: string;
  regulatoryBody: string;
  filingDate: string;
  effectiveDate?: string;
  registrationNumber?: string;
}

/** An appendix entry */
export interface AppendixEntry {
  label: string;
  title: string;
  content: string;
}

/** An exhibit entry for regulatory filings */
export interface ExhibitEntry {
  exhibitNumber: string;
  title: string;
  description: string;
  filePath?: string;
}

/** Composed paper output */
export interface ComposedPaper {
  paperId: string;
  format: PaperFormat;
  title: string;
  authors: string[];
  date: string;
  citationStyle: CitationStyle;
  structure: AcademicStructure | WhitepaperStructure | RegulatoryStructure;
  /** Knowledge nodes that fed into this paper */
  sourceNodes: string[];
  /** Document fingerprint */
  contentHash: string;
  /** Word count statistics */
  wordCount: {
    total: number;
    bySections: Record<string, number>;
  };
}

// ── Peer Review Simulation ───────────────────────────────────

/** Reviewer perspective type */
export type ReviewerType =
  | "academic"
  | "legal"
  | "technical"
  | "economic";

/** Severity levels for review findings */
export type ReviewSeverity =
  | "critical"     // Must be addressed before publication
  | "major"        // Should be addressed
  | "minor"        // Recommended improvement
  | "suggestion";  // Optional enhancement

/** A single review finding */
export interface ReviewFinding {
  findingId: string;
  reviewerType: ReviewerType;
  severity: ReviewSeverity;
  category: string;
  section: string;
  finding: string;
  suggestion: string;
}

/** Peer review report from a single reviewer perspective */
export interface PeerReviewReport {
  reviewId: string;
  paperId: string;
  reviewerType: ReviewerType;
  overallScore: number;           // 0-100
  recommendation: ReviewRecommendation;
  findings: ReviewFinding[];
  structuralIssues: string[];
  citationGaps: string[];
  logicWarnings: string[];
  strengths: string[];
  summary: string;
  reviewedAt: string;
}

/** Reviewer recommendations */
export type ReviewRecommendation =
  | "accept"
  | "accept-with-revisions"
  | "major-revisions"
  | "reject";

/** Multi-reviewer review package */
export interface ReviewPackage {
  packageId: string;
  paperId: string;
  reviews: PeerReviewReport[];
  consensusScore: number;
  consensusRecommendation: ReviewRecommendation;
  createdAt: string;
}

// ── Agreement State Machine ──────────────────────────────────

/** Agreement lifecycle states */
export type AgreementStatus =
  | "draft"
  | "pending-review"
  | "pending-signature"
  | "signed"
  | "active"
  | "amended"
  | "breached"
  | "disputed"
  | "terminated"
  | "completed"
  | "expired"
  | "archived";

/** Obligation tracking */
export interface Obligation {
  obligationId: string;
  description: string;
  assignedTo: string;
  dueDate: string;
  status: "pending" | "fulfilled" | "overdue" | "waived" | "breached";
  completedAt?: string;
  evidence?: string;
}

/** Payment trigger definition */
export interface PaymentTrigger {
  triggerId: string;
  description: string;
  amount: number;
  currency: string;
  triggerCondition: string;
  dueDate?: string;
  status: "pending" | "triggered" | "paid" | "overdue" | "disputed";
  paidAt?: string;
  referenceNumber?: string;
}

/** Deadline entry */
export interface Deadline {
  deadlineId: string;
  description: string;
  date: string;
  type: "hard" | "soft" | "recurring";
  recurringInterval?: string;
  status: "upcoming" | "met" | "missed" | "extended";
  linkedObligationId?: string;
}

/** Amendment record */
export interface Amendment {
  amendmentId: string;
  version: string;
  description: string;
  effectiveDate: string;
  approvedBy: string[];
  contentHash: string;
  cid?: string;
  previousVersion: string;
}

/** The full agreement state object */
export interface AgreementState {
  /** Document / agreement ID */
  agreementId: string;
  /** Human-readable title */
  title: string;
  /** Current lifecycle status */
  status: AgreementStatus;
  /** Parties to the agreement */
  parties: AgreementParty[];
  /** Source document reference */
  sourceDocumentId: string;
  /** SKU of the agreement document */
  sku?: string;
  /** CID on IPFS */
  cid?: string;
  /** Obligations list */
  obligations: Obligation[];
  /** Payment triggers */
  paymentTriggers: PaymentTrigger[];
  /** Deadlines */
  deadlines: Deadline[];
  /** Amendment history */
  amendments: Amendment[];
  /** Status transition history */
  statusHistory: StatusTransition[];
  /** Original execution date */
  executionDate?: string;
  /** Expiration date */
  expirationDate?: string;
  /** Governing law */
  governingLaw?: string;
  /** Content hash */
  contentHash: string;
  /** Created timestamp */
  createdAt: string;
  /** Last updated timestamp */
  updatedAt: string;
}

/** A party to an agreement */
export interface AgreementParty {
  name: string;
  role: "party-a" | "party-b" | "guarantor" | "witness" | "notary";
  email?: string;
  signedAt?: string;
  signatureHash?: string;
}

/** Status transition record */
export interface StatusTransition {
  from: AgreementStatus;
  to: AgreementStatus;
  timestamp: string;
  actor: string;
  reason: string;
  evidence?: string;
}

/** Valid status transitions map */
export const VALID_TRANSITIONS: Record<AgreementStatus, AgreementStatus[]> = {
  "draft": ["pending-review", "pending-signature", "archived"],
  "pending-review": ["draft", "pending-signature", "archived"],
  "pending-signature": ["signed", "draft", "archived"],
  "signed": ["active", "archived"],
  "active": ["amended", "breached", "disputed", "completed", "terminated", "expired"],
  "amended": ["active", "breached", "disputed", "terminated"],
  "breached": ["disputed", "terminated", "active"],
  "disputed": ["active", "terminated", "breached"],
  "terminated": ["archived"],
  "completed": ["archived"],
  "expired": ["archived", "active"],
  "archived": [],
};
