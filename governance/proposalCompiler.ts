// ─────────────────────────────────────────────────────────────
// Proposal Compiler — Compile documents into DAO proposals
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import { DocumentObject } from "../schema/documentSchema";
import { DAOProposalTemplate } from "../schema/daoSchema";
import { formatAsGovernanceProposal, generateGovernanceJSON, generateGovernanceHTML } from "../transform/governanceFormatter";

/**
 * Compile a DocumentObject into a full DAO proposal package.
 * Outputs JSON, HTML, and metadata.
 */
export async function compileProposal(
  doc: DocumentObject,
  outputDir: string,
  options?: {
    author?: string;
    category?: string;
    votingOptions?: string[];
    filename?: string;
  }
): Promise<{
  proposal: DAOProposalTemplate;
  jsonPath: string;
  htmlPath: string;
}> {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Create proposal template
  const proposal = formatAsGovernanceProposal(doc, {
    author: options?.author,
    category: options?.category,
    votingOptions: options?.votingOptions,
  });

  const baseName = options?.filename || `proposal-${proposal.id.toLowerCase()}`;

  // Export proposal JSON
  const jsonPath = path.join(outputDir, `${baseName}.json`);
  fs.writeFileSync(jsonPath, generateGovernanceJSON(proposal), "utf-8");
  console.log(`[GOVERNANCE] Proposal JSON → ${jsonPath}`);

  // Export proposal HTML
  const htmlPath = path.join(outputDir, `${baseName}.html`);
  fs.writeFileSync(htmlPath, generateGovernanceHTML(proposal), "utf-8");
  console.log(`[GOVERNANCE] Proposal HTML → ${htmlPath}`);

  return { proposal, jsonPath, htmlPath };
}

/**
 * Load and validate an existing proposal from JSON.
 */
export function loadProposal(jsonPath: string): DAOProposalTemplate {
  if (!fs.existsSync(jsonPath)) {
    throw new Error(`Proposal file not found: ${jsonPath}`);
  }

  const raw = fs.readFileSync(jsonPath, "utf-8");
  const proposal = JSON.parse(raw) as DAOProposalTemplate;

  // Basic validation
  if (!proposal.id || !proposal.title || !proposal.sections) {
    throw new Error("Invalid proposal format: missing required fields (id, title, sections)");
  }

  return proposal;
}

/**
 * Update proposal status.
 */
export function updateProposalStatus(
  proposal: DAOProposalTemplate,
  newStatus: DAOProposalTemplate["status"]
): DAOProposalTemplate {
  return {
    ...proposal,
    status: newStatus,
  };
}

/**
 * List all proposals in a directory.
 */
export function listProposals(dir: string): DAOProposalTemplate[] {
  if (!fs.existsSync(dir)) return [];

  return fs
    .readdirSync(dir)
    .filter((f) => f.startsWith("proposal-") && f.endsWith(".json"))
    .map((f) => {
      try {
        return loadProposal(path.join(dir, f));
      } catch {
        return null;
      }
    })
    .filter((p): p is DAOProposalTemplate => p !== null);
}
