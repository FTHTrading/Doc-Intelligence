// ─────────────────────────────────────────────────────────────
// Governance Formatter — Convert documents to DAO proposals
// ─────────────────────────────────────────────────────────────

import { DocumentObject, Section } from "../schema/documentSchema";
import {
  DAOProposalTemplate,
  DEFAULT_QUORUM,
  DEFAULT_VOTING_OPTIONS,
  OnchainReference,
  DocumentRevision,
} from "../schema/daoSchema";

/**
 * Convert a DocumentObject into a DAO governance proposal template.
 */
export function formatAsGovernanceProposal(
  doc: DocumentObject,
  options?: {
    author?: string;
    category?: string;
    votingOptions?: string[];
  }
): DAOProposalTemplate {
  const proposal: DAOProposalTemplate = {
    id: generateProposalId(),
    title: doc.metadata.title,
    category: options?.category || inferCategory(doc.semanticTags),
    author: options?.author || "System",
    createdAt: new Date().toISOString(),
    status: "draft",
    sections: sanitizeSectionsForGovernance(doc.structure),
    votingStrategy: "simple-majority",
    votingOptions: options?.votingOptions || DEFAULT_VOTING_OPTIONS,
    quorumRules: { ...DEFAULT_QUORUM },
    executionLogic: {
      type: "manual",
    },
    tags: [...doc.semanticTags, "governance-proposal"],
  };

  return proposal;
}

/**
 * Generate a governance JSON output for DAO submission.
 */
export function generateGovernanceJSON(proposal: DAOProposalTemplate): string {
  return JSON.stringify(proposal, null, 2);
}

/**
 * Generate a governance-formatted HTML view of the proposal.
 */
export function generateGovernanceHTML(proposal: DAOProposalTemplate): string {
  const sectionsHTML = proposal.sections
    .map((s) => renderGovernanceSection(s))
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(proposal.title)} — Governance Proposal</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; color: #1a1a2e; }
    .proposal-header { background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }
    .proposal-header h1 { margin: 0 0 8px 0; font-size: 28px; }
    .proposal-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px; opacity: 0.85; }
    .proposal-body { padding: 0 10px; }
    .voting-section { background: #f7f7fb; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 30px 0; }
    .voting-option { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid #eee; }
    .voting-option:last-child { border-bottom: none; }
    .quorum-info { font-size: 13px; color: #555; margin-top: 15px; }
    .status-badge { display: inline-block; background: #e94560; color: white; padding: 3px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
    .section-block { margin: 15px 0; padding: 10px 0; border-bottom: 1px solid #f0f0f0; }
    .section-label { font-weight: 600; color: #16213e; font-size: 13px; margin-bottom: 4px; }
    .section-content { min-height: 20px; padding: 8px; border: 1px dashed #ccc; border-radius: 4px; }
    .section-content[contenteditable]:focus { border-color: #e94560; background: #fef2f4; outline: none; }
    footer { text-align: center; font-size: 11px; color: #999; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; }
  </style>
</head>
<body>
  <div class="proposal-header">
    <span class="status-badge">${proposal.status.toUpperCase()}</span>
    <h1>${escapeHtml(proposal.title)}</h1>
    <div class="proposal-meta">
      <div>ID: ${proposal.id}</div>
      <div>Category: ${escapeHtml(proposal.category)}</div>
      <div>Author: ${escapeHtml(proposal.author)}</div>
      <div>Created: ${new Date(proposal.createdAt).toLocaleDateString()}</div>
    </div>
  </div>

  <div class="proposal-body">
${sectionsHTML}
  </div>

  <div class="voting-section">
    <h3>Voting</h3>
    <div><strong>Strategy:</strong> ${proposal.votingStrategy.replace(/-/g, " ")}</div>
${proposal.votingOptions.map((opt) => `    <div class="voting-option"><input type="radio" name="vote" disabled /> ${escapeHtml(opt)}</div>`).join("\n")}
    <div class="quorum-info">
      <strong>Quorum:</strong> ${proposal.quorumRules.minParticipation}% participation required |
      ${proposal.quorumRules.minApproval}% approval needed |
      Voting period: ${proposal.quorumRules.votingPeriodHours}h
    </div>
  </div>

  <footer>
    Document Intelligence Engine — Governance Proposal Template<br>
    Tags: ${proposal.tags.join(", ")}
  </footer>
</body>
</html>`;
}

// ── Helpers ──────────────────────────────────────────────────

function generateProposalId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `PROP-${timestamp}-${random}`.toUpperCase();
}

function inferCategory(tags: string[]): string {
  if (tags.includes("grant-application")) return "Grant";
  if (tags.includes("legal-agreement")) return "Legal";
  if (tags.includes("financial-document")) return "Financial";
  if (tags.includes("governance-proposal")) return "Governance";
  if (tags.includes("compliance-form")) return "Compliance";
  if (tags.includes("educational-material")) return "Education";
  if (tags.includes("policy-document")) return "Policy";
  return "General";
}

function sanitizeSectionsForGovernance(sections: Section[]): Section[] {
  return sections.map((s) => ({
    ...s,
    content: "", // always empty in template mode
    children: sanitizeSectionsForGovernance(s.children),
  }));
}

function renderGovernanceSection(section: Section): string {
  const label = section.label ? escapeHtml(section.label) : section.type.replace(/-/g, " ");
  let html = `    <div class="section-block">\n`;
  html += `      <div class="section-label">${label}</div>\n`;
  html += `      <div class="section-content" contenteditable="true"></div>\n`;
  html += `    </div>\n`;
  return html;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export { DocumentRevision, OnchainReference };
