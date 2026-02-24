// ─────────────────────────────────────────────────────────────
// DAO Governance Schema — Document → Proposal Conversion
// ─────────────────────────────────────────────────────────────

import { Section, SectionStyle } from "./documentSchema";

/** Voting strategy types */
export type VotingStrategy = "simple-majority" | "supermajority" | "quadratic" | "token-weighted" | "one-person-one-vote";

/** Proposal status lifecycle */
export type ProposalStatus = "draft" | "submitted" | "voting" | "approved" | "rejected" | "executed" | "archived";

/** Quorum rules for governance voting */
export interface QuorumRules {
  minParticipation: number;       // percentage 0-100
  minApproval: number;            // percentage 0-100
  votingPeriodHours: number;
  gracePeriodHours: number;
  vetoThreshold?: number;
}

/** Execution logic after proposal approval */
export interface ExecutionLogic {
  type: "manual" | "automatic" | "smart-contract";
  contractAddress?: string;
  functionSignature?: string;
  parameters?: Record<string, unknown>;
  timelockHours?: number;
}

/** A DAO governance proposal template derived from a document */
export interface DAOProposalTemplate {
  id: string;
  title: string;
  category: string;
  author: string;
  createdAt: string;
  status: ProposalStatus;
  sections: Section[];
  votingStrategy: VotingStrategy;
  votingOptions: string[];
  quorumRules: QuorumRules;
  executionLogic: ExecutionLogic;
  tags: string[];
  linkedDocumentHash?: string;
  onchainReference?: OnchainReference;
}

/** Blockchain anchor reference */
export interface OnchainReference {
  chain: "xrpl" | "stellar" | "ethereum" | "polygon" | "ipfs";
  transactionHash?: string;
  contractAddress?: string;
  ipfsCid?: string;
  anchoredAt?: string;
}

/** Revision tracking for governance documents */
export interface DocumentRevision {
  version: string;
  hash: string;
  changedBy: string;
  changedAt: string;
  changeDescription: string;
  previousVersion?: string;
}

/** Default quorum rules */
export const DEFAULT_QUORUM: QuorumRules = {
  minParticipation: 51,
  minApproval: 51,
  votingPeriodHours: 72,
  gracePeriodHours: 24,
};

/** Default voting options */
export const DEFAULT_VOTING_OPTIONS = ["Approve", "Reject", "Abstain"];
