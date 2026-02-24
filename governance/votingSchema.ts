// ─────────────────────────────────────────────────────────────
// Voting Schema — DAO Voting Structures & Logic
// ─────────────────────────────────────────────────────────────

import { VotingStrategy, QuorumRules, DEFAULT_QUORUM } from "../schema/daoSchema";

/** A single vote cast */
export interface Vote {
  voter: string;
  option: string;
  weight: number;
  timestamp: string;
  signature?: string;
}

/** Complete voting session */
export interface VotingSession {
  proposalId: string;
  strategy: VotingStrategy;
  quorum: QuorumRules;
  votes: Vote[];
  startedAt: string;
  endsAt: string;
  finalized: boolean;
  result?: VotingResult;
}

/** Voting result after tallying */
export interface VotingResult {
  totalVotes: number;
  totalWeight: number;
  breakdown: Record<string, { count: number; weight: number }>;
  quorumMet: boolean;
  approved: boolean;
  winningOption: string;
  finalizedAt: string;
}

/**
 * Create a new voting session for a proposal.
 */
export function createVotingSession(
  proposalId: string,
  strategy: VotingStrategy = "simple-majority",
  quorum: QuorumRules = DEFAULT_QUORUM,
  votingOptions: string[] = ["Approve", "Reject", "Abstain"]
): VotingSession {
  const now = new Date();
  const endsAt = new Date(now.getTime() + quorum.votingPeriodHours * 60 * 60 * 1000);

  return {
    proposalId,
    strategy,
    quorum,
    votes: [],
    startedAt: now.toISOString(),
    endsAt: endsAt.toISOString(),
    finalized: false,
  };
}

/**
 * Cast a vote in a session.
 */
export function castVote(
  session: VotingSession,
  voter: string,
  option: string,
  weight: number = 1
): VotingSession {
  if (session.finalized) {
    throw new Error("Voting session is already finalized.");
  }

  if (new Date() > new Date(session.endsAt)) {
    throw new Error("Voting period has ended.");
  }

  // Check for duplicate voters
  if (session.votes.some((v) => v.voter === voter)) {
    throw new Error(`Voter "${voter}" has already cast a vote.`);
  }

  const vote: Vote = {
    voter,
    option,
    weight: session.strategy === "one-person-one-vote" ? 1 : weight,
    timestamp: new Date().toISOString(),
  };

  return {
    ...session,
    votes: [...session.votes, vote],
  };
}

/**
 * Tally votes and finalize the session.
 */
export function tallyVotes(
  session: VotingSession,
  totalEligibleVoters: number
): VotingSession {
  const breakdown: Record<string, { count: number; weight: number }> = {};

  for (const vote of session.votes) {
    if (!breakdown[vote.option]) {
      breakdown[vote.option] = { count: 0, weight: 0 };
    }
    breakdown[vote.option].count += 1;
    breakdown[vote.option].weight += vote.weight;
  }

  const totalVotes = session.votes.length;
  const totalWeight = session.votes.reduce((sum, v) => sum + v.weight, 0);

  // Check quorum
  const participationRate = (totalVotes / totalEligibleVoters) * 100;
  const quorumMet = participationRate >= session.quorum.minParticipation;

  // Determine winner
  let winningOption = "";
  let maxWeight = 0;

  for (const [option, data] of Object.entries(breakdown)) {
    if (option === "Abstain") continue;
    const effectiveWeight = session.strategy === "one-person-one-vote" ? data.count : data.weight;
    if (effectiveWeight > maxWeight) {
      maxWeight = effectiveWeight;
      winningOption = option;
    }
  }

  // Check approval threshold
  const totalNonAbstain = Object.entries(breakdown)
    .filter(([opt]) => opt !== "Abstain")
    .reduce((sum, [, data]) => sum + (session.strategy === "one-person-one-vote" ? data.count : data.weight), 0);

  const approvalRate = totalNonAbstain > 0 ? (maxWeight / totalNonAbstain) * 100 : 0;
  const approved = quorumMet && approvalRate >= session.quorum.minApproval && winningOption === "Approve";

  const result: VotingResult = {
    totalVotes,
    totalWeight,
    breakdown,
    quorumMet,
    approved,
    winningOption,
    finalizedAt: new Date().toISOString(),
  };

  return {
    ...session,
    finalized: true,
    result,
  };
}
