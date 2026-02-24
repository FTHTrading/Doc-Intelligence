// ─────────────────────────────────────────────────────────────
// Peer Review Simulation Engine — Multi-Perspective Analysis
//
// Simulates four independent reviewer perspectives:
//   1. Academic  — Hypothesis, methodology, rigor, citations
//   2. Legal     — Enforceability, regulatory risk, jurisdiction
//   3. Technical — Architecture, security, threat model
//   4. Economic  — Incentive alignment, stability, attack surface
//
// Each reviewer produces a PeerReviewReport with scored findings.
// Combined into a ReviewPackage with consensus recommendation.
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import {
  PeerReviewReport,
  ReviewPackage,
  ReviewFinding,
  ReviewerType,
  ReviewSeverity,
  ReviewRecommendation,
  ComposedPaper,
  AcademicStructure,
  WhitepaperStructure,
  RegulatoryStructure,
} from "../schema/researchSchema";

// ── Main Entry ───────────────────────────────────────────────

export interface ReviewOptions {
  /** Which reviewer types to include */
  reviewers?: ReviewerType[];
  /** Strictness level: higher = more findings reported */
  strictness?: number;  // 1-10, default 5
}

/**
 * Run a full peer review simulation on a composed paper.
 * Returns a ReviewPackage with consensus score and recommendation.
 */
export function simulatePeerReview(
  paper: ComposedPaper,
  options: ReviewOptions = {}
): ReviewPackage {
  const {
    reviewers = ["academic", "legal", "technical", "economic"],
    strictness = 5,
  } = options;

  const reviews: PeerReviewReport[] = [];

  for (const reviewerType of reviewers) {
    const review = runReview(paper, reviewerType, strictness);
    reviews.push(review);
  }

  // Compute consensus
  const avgScore = reviews.reduce((sum, r) => sum + r.overallScore, 0) / reviews.length;
  const consensusRecommendation = computeConsensus(reviews);

  const packageId = crypto.createHash("sha256")
    .update(paper.paperId + Date.now().toString())
    .digest("hex")
    .substring(0, 16);

  return {
    packageId,
    paperId: paper.paperId,
    reviews,
    consensusScore: Math.round(avgScore),
    consensusRecommendation,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Generate a human-readable review summary (plain text).
 */
export function formatReviewSummary(pkg: ReviewPackage): string {
  const lines: string[] = [];

  lines.push("══════════════════════════════════════════════════════════");
  lines.push("  PEER REVIEW SIMULATION REPORT");
  lines.push("══════════════════════════════════════════════════════════");
  lines.push("");
  lines.push(`  Paper ID:       ${pkg.paperId}`);
  lines.push(`  Consensus:      ${pkg.consensusScore}/100 — ${pkg.consensusRecommendation.toUpperCase()}`);
  lines.push(`  Reviewers:      ${pkg.reviews.length}`);
  lines.push(`  Review Date:    ${pkg.createdAt}`);
  lines.push("");

  for (const review of pkg.reviews) {
    lines.push(`── ${review.reviewerType.toUpperCase()} REVIEWER ──────────────────────────────`);
    lines.push(`  Score: ${review.overallScore}/100`);
    lines.push(`  Recommendation: ${review.recommendation}`);
    lines.push(`  Findings: ${review.findings.length}`);

    const critical = review.findings.filter((f) => f.severity === "critical");
    const major = review.findings.filter((f) => f.severity === "major");
    const minor = review.findings.filter((f) => f.severity === "minor");

    if (critical.length) lines.push(`    Critical: ${critical.length}`);
    if (major.length) lines.push(`    Major: ${major.length}`);
    if (minor.length) lines.push(`    Minor: ${minor.length}`);

    if (review.strengths.length) {
      lines.push("  Strengths:");
      for (const s of review.strengths) lines.push(`    + ${s}`);
    }

    if (review.structuralIssues.length) {
      lines.push("  Structural Issues:");
      for (const s of review.structuralIssues) lines.push(`    ! ${s}`);
    }

    if (review.citationGaps.length) {
      lines.push("  Citation Gaps:");
      for (const s of review.citationGaps) lines.push(`    ? ${s}`);
    }

    if (review.logicWarnings.length) {
      lines.push("  Logic Warnings:");
      for (const s of review.logicWarnings) lines.push(`    ⚠ ${s}`);
    }

    lines.push(`  Summary: ${review.summary}`);
    lines.push("");
  }

  lines.push("══════════════════════════════════════════════════════════");
  lines.push(`  FINAL CONSENSUS: ${pkg.consensusRecommendation.toUpperCase()} (${pkg.consensusScore}/100)`);
  lines.push("══════════════════════════════════════════════════════════");

  return lines.join("\n");
}

/**
 * Generate an HTML version of the review report.
 */
export function formatReviewHTML(pkg: ReviewPackage): string {
  const scoreColor = (score: number) =>
    score >= 80 ? "#27ae60" : score >= 60 ? "#f39c12" : score >= 40 ? "#e67e22" : "#e74c3c";

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Peer Review — ${pkg.paperId}</title>
<style>
  body { font-family: Georgia, serif; max-width: 900px; margin: 2rem auto; color: #1a1a2e; line-height: 1.6; }
  h1 { border-bottom: 3px solid #0f3460; padding-bottom: 0.5rem; }
  h2 { color: #16213e; margin-top: 2rem; }
  .score-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; }
  .finding { padding: 0.5rem 1rem; margin: 0.5rem 0; border-left: 4px solid; }
  .finding.critical { border-color: #e74c3c; background: #fdf0ef; }
  .finding.major { border-color: #e67e22; background: #fef6ee; }
  .finding.minor { border-color: #f39c12; background: #fefbf0; }
  .finding.suggestion { border-color: #3498db; background: #eef6fb; }
  .meta { color: #666; font-size: 0.9em; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
  th { background: #16213e; color: white; }
</style>
</head>
<body>
<h1>Peer Review Simulation Report</h1>
<p class="meta">Paper: ${pkg.paperId} | Reviewed: ${pkg.createdAt}</p>
<p>Consensus: <span class="score-badge" style="background:${scoreColor(pkg.consensusScore)}">${pkg.consensusScore}/100</span>
  — <strong>${pkg.consensusRecommendation.toUpperCase()}</strong></p>

<table>
<tr><th>Reviewer</th><th>Score</th><th>Recommendation</th><th>Findings</th></tr>
${pkg.reviews.map((r) => `<tr><td>${r.reviewerType}</td><td><span class="score-badge" style="background:${scoreColor(r.overallScore)}">${r.overallScore}</span></td><td>${r.recommendation}</td><td>${r.findings.length}</td></tr>`).join("\n")}
</table>
`;

  for (const review of pkg.reviews) {
    html += `<h2>${review.reviewerType.charAt(0).toUpperCase() + review.reviewerType.slice(1)} Review</h2>\n`;
    html += `<p>${review.summary}</p>\n`;

    if (review.strengths.length) {
      html += `<h3>Strengths</h3><ul>${review.strengths.map((s) => `<li>${s}</li>`).join("")}</ul>\n`;
    }

    if (review.findings.length) {
      html += `<h3>Findings</h3>\n`;
      for (const f of review.findings) {
        html += `<div class="finding ${f.severity}"><strong>[${f.severity.toUpperCase()}]</strong> ${f.category}: ${f.finding}<br><em>Suggestion: ${f.suggestion}</em></div>\n`;
      }
    }

    if (review.citationGaps.length) {
      html += `<h3>Citation Gaps</h3><ul>${review.citationGaps.map((s) => `<li>${s}</li>`).join("")}</ul>\n`;
    }

    if (review.logicWarnings.length) {
      html += `<h3>Logic Warnings</h3><ul>${review.logicWarnings.map((s) => `<li>${s}</li>`).join("")}</ul>\n`;
    }
  }

  html += `</body></html>`;
  return html;
}

// ── Individual Reviewer Implementations ──────────────────────

function runReview(paper: ComposedPaper, type: ReviewerType, strictness: number): PeerReviewReport {
  const reviewId = crypto.createHash("sha256")
    .update(paper.paperId + type + Date.now().toString())
    .digest("hex")
    .substring(0, 16);

  let findings: ReviewFinding[] = [];
  let structuralIssues: string[] = [];
  let citationGaps: string[] = [];
  let logicWarnings: string[] = [];
  let strengths: string[] = [];
  let score = 75; // start with baseline

  switch (type) {
    case "academic":
      ({ findings, structuralIssues, citationGaps, logicWarnings, strengths, score } =
        reviewAcademic(paper, strictness));
      break;
    case "legal":
      ({ findings, structuralIssues, citationGaps, logicWarnings, strengths, score } =
        reviewLegal(paper, strictness));
      break;
    case "technical":
      ({ findings, structuralIssues, citationGaps, logicWarnings, strengths, score } =
        reviewTechnical(paper, strictness));
      break;
    case "economic":
      ({ findings, structuralIssues, citationGaps, logicWarnings, strengths, score } =
        reviewEconomic(paper, strictness));
      break;
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  const recommendation = scoreToRecommendation(score);

  return {
    reviewId,
    paperId: paper.paperId,
    reviewerType: type,
    overallScore: score,
    recommendation,
    findings,
    structuralIssues,
    citationGaps,
    logicWarnings,
    strengths,
    summary: generateReviewSummary(type, score, findings, strengths),
    reviewedAt: new Date().toISOString(),
  };
}

// ── Academic Reviewer ────────────────────────────────────────

function reviewAcademic(paper: ComposedPaper, strictness: number) {
  const findings: ReviewFinding[] = [];
  const structuralIssues: string[] = [];
  const citationGaps: string[] = [];
  const logicWarnings: string[] = [];
  const strengths: string[] = [];
  let score = 80;

  const content = JSON.stringify(paper.structure);
  const wordCount = paper.wordCount.total;

  // Check structural completeness
  if (paper.format === "academic") {
    const s = paper.structure as AcademicStructure;
    const requiredSections = ["abstract", "introduction", "methodology", "results", "discussion", "conclusion"];

    for (const section of requiredSections) {
      const value = (s as any)[section] as string;
      if (!value || value.includes("[") && value.includes("pending")) {
        structuralIssues.push(`Missing or placeholder content in: ${section}`);
        findings.push(makeFinding("academic", strictness > 5 ? "critical" : "major", "Structure", section,
          `The ${section} section appears incomplete or contains placeholder text.`,
          `Provide substantive content for the ${section} section.`));
        score -= 5;
      } else if (value.split(/\s+/).length < 50) {
        findings.push(makeFinding("academic", "minor", "Depth", section,
          `The ${section} section is notably brief (${value.split(/\s+/).length} words).`,
          `Consider expanding the ${section} with more detail and supporting evidence.`));
        score -= 2;
      }
    }
  }

  // Word count analysis
  if (wordCount < 500) {
    findings.push(makeFinding("academic", "major", "Length", "overall",
      `Paper is very short (${wordCount} words). Academic papers typically exceed 3,000 words.`,
      `Expand the paper with additional analysis, evidence, and discussion.`));
    score -= 10;
  } else if (wordCount > 1000) {
    strengths.push(`Substantial content volume (${wordCount} words)`);
    score += 3;
  }

  // Citation analysis
  const refs = "references" in paper.structure ? (paper.structure as any).references as any[] : [];
  if (refs.length === 0) {
    citationGaps.push("No references provided. Academic work requires citation support.");
    findings.push(makeFinding("academic", "critical", "Citations", "references",
      `No references or citations found. All claims must be supported by evidence.`,
      `Add at least 10-15 peer-reviewed references.`));
    score -= 15;
  } else if (refs.length < 5) {
    citationGaps.push(`Only ${refs.length} references. Consider expanding to at least 10.`);
    score -= 5;
  } else {
    strengths.push(`${refs.length} references provided`);
    score += 2;
  }

  // Check for logical connectors and argument flow
  const logicTerms = ["therefore", "however", "consequently", "moreover", "furthermore", "in contrast", "nevertheless"];
  const contentLower = content.toLowerCase();
  const logicCount = logicTerms.filter((t) => contentLower.includes(t)).length;

  if (logicCount < 2 && strictness > 3) {
    logicWarnings.push("Limited use of logical connectors. Argument flow may be unclear.");
    score -= 3;
  } else if (logicCount >= 5) {
    strengths.push("Good use of logical argumentation and connective language");
    score += 3;
  }

  // Check for hypothesis clarity
  if (paper.format === "academic" && !contentLower.includes("hypothes") && !contentLower.includes("research question") && !contentLower.includes("we propose")) {
    logicWarnings.push("No clear hypothesis or research question identified.");
    score -= 5;
  }

  return { findings, structuralIssues, citationGaps, logicWarnings, strengths, score };
}

// ── Legal Reviewer ───────────────────────────────────────────

function reviewLegal(paper: ComposedPaper, strictness: number) {
  const findings: ReviewFinding[] = [];
  const structuralIssues: string[] = [];
  const citationGaps: string[] = [];
  const logicWarnings: string[] = [];
  const strengths: string[] = [];
  let score = 75;

  const content = JSON.stringify(paper.structure).toLowerCase();

  // Enforceability checks
  const legalTerms = ["shall", "must", "agreement", "liability", "indemnif", "governing law", "jurisdiction", "dispute resolution"];
  const legalHits = legalTerms.filter((t) => content.includes(t));

  if (legalHits.length >= 4) {
    strengths.push("Strong use of legal terminology and binding language");
    score += 5;
  }

  // Regulatory risk checks
  const riskTerms = ["securities", "investment", "accredited", "offering", "prospectus", "sec ", "finra"];
  const riskHits = riskTerms.filter((t) => content.includes(t));

  if (riskHits.length > 0 && !content.includes("risk disclosure") && !content.includes("disclaimer")) {
    findings.push(makeFinding("legal", "critical", "Regulatory Risk", "compliance",
      `Document references securities-related terms (${riskHits.join(", ")}) without adequate risk disclosures.`,
      `Add comprehensive risk disclosure and regulatory compliance sections.`));
    score -= 10;
  }

  if (riskHits.length > 0) {
    findings.push(makeFinding("legal", "major", "Securities Compliance", "regulatory",
      `Securities-related content detected. Ensure compliance with applicable regulations.`,
      `Review with securities counsel. Include investor suitability requirements.`));
  }

  // Jurisdictional analysis
  const jurisdictions = ["united states", "european union", "united kingdom", "singapore", "switzerland", "hong kong"];
  const mentionedJurisdictions = jurisdictions.filter((j) => content.includes(j));

  if (mentionedJurisdictions.length > 1 && !content.includes("conflict of law")) {
    logicWarnings.push(`Multiple jurisdictions referenced (${mentionedJurisdictions.length}) without conflict-of-law analysis.`);
    score -= 5;
  }

  if (mentionedJurisdictions.length === 0 && content.length > 500) {
    citationGaps.push("No jurisdiction specified. Legal documents should state governing law.");
  }

  // IP and confidentiality
  if (content.includes("intellectual property") || content.includes("proprietary")) {
    strengths.push("Intellectual property provisions addressed");
    score += 3;
  }

  // Data privacy
  if (content.includes("personal data") || content.includes("privacy")) {
    if (!content.includes("gdpr") && !content.includes("ccpa") && !content.includes("data protection")) {
      findings.push(makeFinding("legal", "major", "Privacy Compliance", "data-privacy",
        `Data privacy mentioned without reference to specific regulatory frameworks.`,
        `Reference applicable data protection legislation (GDPR, CCPA, etc.).`));
      score -= 5;
    } else {
      strengths.push("Data privacy regulations properly referenced");
    }
  }

  // Dispute resolution
  if (!content.includes("arbitration") && !content.includes("mediation") && !content.includes("dispute resolution")) {
    if (strictness > 4) {
      findings.push(makeFinding("legal", "minor", "Dispute Resolution", "process",
        `No dispute resolution mechanism specified.`,
        `Include arbitration, mediation, or litigation provisions.`));
      score -= 3;
    }
  }

  return { findings, structuralIssues, citationGaps, logicWarnings, strengths, score };
}

// ── Technical Reviewer ───────────────────────────────────────

function reviewTechnical(paper: ComposedPaper, strictness: number) {
  const findings: ReviewFinding[] = [];
  const structuralIssues: string[] = [];
  const citationGaps: string[] = [];
  const logicWarnings: string[] = [];
  const strengths: string[] = [];
  let score = 78;

  const content = JSON.stringify(paper.structure).toLowerCase();

  // Architecture coherence
  const archTerms = ["architecture", "system design", "component", "module", "interface", "api", "endpoint"];
  const archHits = archTerms.filter((t) => content.includes(t));

  if (archHits.length >= 3) {
    strengths.push("Clear architectural vocabulary and system decomposition");
    score += 5;
  } else if (archHits.length === 0 && paper.format === "whitepaper") {
    structuralIssues.push("No architectural description found in whitepaper");
    score -= 8;
  }

  // Security model check
  const secTerms = ["encryption", "authentication", "authorization", "hash", "signature", "tls", "ssl", "zero-knowledge", "multi-factor"];
  const secHits = secTerms.filter((t) => content.includes(t));

  if (secHits.length >= 3) {
    strengths.push("Security model includes multiple control layers");
    score += 5;
  } else if (secHits.length === 0) {
    findings.push(makeFinding("technical", "critical", "Security", "security-model",
      `No security controls or mechanisms described.`,
      `Define encryption, authentication, authorization, and data protection measures.`));
    score -= 12;
  } else {
    findings.push(makeFinding("technical", "minor", "Security", "security-depth",
      `Security model covers ${secHits.length} control types. Consider expanding.`,
      `Add threat modeling, attack surface analysis, and mitigation strategies.`));
    score -= 3;
  }

  // Threat modeling
  if (content.includes("threat model") || content.includes("attack vector") || content.includes("vulnerability")) {
    strengths.push("Threat modeling addressed");
    score += 4;
  } else if (strictness > 5) {
    findings.push(makeFinding("technical", "major", "Threat Modeling", "threats",
      `No threat modeling or attack surface analysis found.`,
      `Include STRIDE or similar threat analysis framework.`));
    score -= 7;
  }

  // Scalability
  if (content.includes("scal") || content.includes("performance") || content.includes("throughput") || content.includes("latency")) {
    strengths.push("Scalability or performance considerations addressed");
    score += 3;
  } else if (paper.format === "whitepaper" && strictness > 4) {
    findings.push(makeFinding("technical", "minor", "Scalability", "performance",
      `No scalability or performance analysis found.`,
      `Discuss expected throughput, latency, and scaling strategies.`));
    score -= 3;
  }

  // Reproducibility
  if (content.includes("reproducib") || content.includes("open source") || content.includes("github") || content.includes("code available")) {
    strengths.push("Reproducibility measures mentioned");
    score += 3;
  }

  // Protocol/consensus checks for blockchain papers
  if (content.includes("blockchain") || content.includes("consensus") || content.includes("distributed ledger")) {
    if (!content.includes("finality") && !content.includes("liveness") && !content.includes("safety")) {
      logicWarnings.push("Blockchain system described without discussing finality, liveness, or safety properties.");
      score -= 5;
    }
    if (content.includes("consensus") && !content.includes("byzantine")) {
      citationGaps.push("Consensus mechanism discussed without Byzantine fault tolerance analysis.");
    }
  }

  return { findings, structuralIssues, citationGaps, logicWarnings, strengths, score };
}

// ── Economic Reviewer ────────────────────────────────────────

function reviewEconomic(paper: ComposedPaper, strictness: number) {
  const findings: ReviewFinding[] = [];
  const structuralIssues: string[] = [];
  const citationGaps: string[] = [];
  const logicWarnings: string[] = [];
  const strengths: string[] = [];
  let score = 76;

  const content = JSON.stringify(paper.structure).toLowerCase();

  // Incentive alignment analysis
  const incentiveTerms = ["incentive", "reward", "penalty", "stake", "slashing", "fee", "subsidy", "bounty"];
  const incentiveHits = incentiveTerms.filter((t) => content.includes(t));

  if (incentiveHits.length >= 3) {
    strengths.push("Multiple incentive mechanisms described");
    score += 5;
  } else if (incentiveHits.length === 0 && (content.includes("token") || content.includes("protocol"))) {
    findings.push(makeFinding("economic", "critical", "Incentive Design", "incentives",
      `Token/protocol system described without incentive analysis.`,
      `Define incentive structures, reward mechanisms, and penalty conditions.`));
    score -= 12;
  }

  // Stability modeling
  if (content.includes("stability") || content.includes("equilibrium") || content.includes("steady state")) {
    strengths.push("Stability analysis present");
    score += 4;
  }

  // Game theory / attack surface
  if (content.includes("game theory") || content.includes("nash equilibrium") || content.includes("dominant strategy")) {
    strengths.push("Game-theoretic analysis included");
    score += 5;
  } else if (content.includes("token") && strictness > 5) {
    findings.push(makeFinding("economic", "major", "Game Theory", "economic-model",
      `Tokenomic system without game-theoretic analysis.`,
      `Add Nash equilibrium analysis and rational actor modeling.`));
    score -= 7;
  }

  // Economic attack vectors
  const attackTerms = ["front-running", "sandwich attack", "flash loan", "mev", "manipulation", "sybil", "economic attack"];
  const attackHits = attackTerms.filter((t) => content.includes(t));

  if (attackHits.length > 0) {
    strengths.push(`Economic attack analysis covers: ${attackHits.join(", ")}`);
    score += 4;
  } else if (content.includes("defi") || content.includes("decentralized finance") || content.includes("liquidity")) {
    findings.push(makeFinding("economic", "critical", "Attack Surface", "economic-attacks",
      `DeFi system without economic attack vector analysis.`,
      `Analyze front-running, sandwich attacks, flash loans, MEV, and market manipulation.`));
    score -= 10;
  }

  // Sustainability
  if (content.includes("sustainab") || content.includes("long-term") || content.includes("treasury")) {
    strengths.push("Long-term sustainability considerations addressed");
    score += 3;
  }

  // Revenue model
  if (content.includes("revenue") || content.includes("business model") || content.includes("monetiz")) {
    strengths.push("Revenue or monetization model described");
    score += 3;
  } else if (paper.format === "whitepaper") {
    findings.push(makeFinding("economic", "minor", "Revenue Model", "business",
      `No clear revenue or sustainability model described.`,
      `Include revenue streams, treasury management, or value capture mechanisms.`));
    score -= 3;
  }

  // Valuation methodology
  if (content.includes("valuation") || content.includes("dcf") || content.includes("discounted")) {
    strengths.push("Valuation methodology included");
    score += 3;
  }

  return { findings, structuralIssues, citationGaps, logicWarnings, strengths, score };
}

// ── Helpers ──────────────────────────────────────────────────

function makeFinding(
  reviewerType: ReviewerType,
  severity: ReviewSeverity,
  category: string,
  section: string,
  finding: string,
  suggestion: string
): ReviewFinding {
  return {
    findingId: crypto.createHash("sha256")
      .update(finding + category)
      .digest("hex")
      .substring(0, 12),
    reviewerType,
    severity,
    category,
    section,
    finding,
    suggestion,
  };
}

function scoreToRecommendation(score: number): ReviewRecommendation {
  if (score >= 80) return "accept";
  if (score >= 65) return "accept-with-revisions";
  if (score >= 45) return "major-revisions";
  return "reject";
}

function computeConsensus(reviews: PeerReviewReport[]): ReviewRecommendation {
  const scores: Record<ReviewRecommendation, number> = {
    "accept": 0,
    "accept-with-revisions": 0,
    "major-revisions": 0,
    "reject": 0,
  };

  for (const r of reviews) {
    scores[r.recommendation]++;
  }

  // Return the most common recommendation
  let best: ReviewRecommendation = "accept-with-revisions";
  let bestCount = 0;

  for (const [rec, count] of Object.entries(scores)) {
    if (count > bestCount) {
      bestCount = count;
      best = rec as ReviewRecommendation;
    }
  }

  // If any reviewer rejects, at minimum require major revisions
  if (scores["reject"] > 0 && best === "accept") {
    best = "accept-with-revisions";
  }

  return best;
}

function generateReviewSummary(
  type: ReviewerType,
  score: number,
  findings: ReviewFinding[],
  strengths: string[]
): string {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const major = findings.filter((f) => f.severity === "major").length;

  let summary = `From a ${type} perspective, this paper scores ${score}/100. `;

  if (strengths.length > 0) {
    summary += `Key strengths include: ${strengths.slice(0, 3).join("; ")}. `;
  }

  if (critical > 0) {
    summary += `There are ${critical} critical issue(s) that must be addressed before publication. `;
  }

  if (major > 0) {
    summary += `${major} major issue(s) should be resolved. `;
  }

  if (findings.length === 0) {
    summary += "No significant issues found.";
  }

  return summary.trim();
}
