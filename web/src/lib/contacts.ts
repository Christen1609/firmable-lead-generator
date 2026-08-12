/**
 * Ranking for the Contact Info feature.
 *
 * A salesperson opening a Critical company wants the person who owns the
 * problem, not whoever the provider happened to list first. Security leadership
 * outranks general technical leadership, which outranks a founder or owner who
 * would have to forward the mail on.
 *
 * Pure functions, no provider types — the ranking should not care whether the
 * contacts came from Hunter, Apollo or anything else.
 */

export type ContactRank = "security" | "technical" | "decision-maker" | "other";

export interface RankedContact {
  name: string | null;
  position: string | null;
  email: string;
  rank: ContactRank;
  /** Why this rank, shown in the UI so the ordering is not a black box. */
  rankReason: string;
  confidence: number | null;
  linkedin: string | null;
  /** Set when the record looked unreliable and was demoted a level. */
  downgraded: boolean;
  seniority: string | null;
  decisionMaker: boolean;
}

const LEADERSHIP = /\b(chief|head|director|vp|vice president|lead|manager|principal|officer)\b/i;
const SECURITY = /\b(security|infosec|cyber|ciso|cso)\b/i;

/** Ordered most to least specific — the first match wins. */
const TECHNICAL_TITLES = [
  /\bcto\b|chief technology officer/i,
  /\bcio\b|chief information officer/i,
  /\b(vp|vice president|head|director)\b.*\b(engineering|infrastructure|technology|technical|it|platform|devops)\b/i,
  /\bit\b.*\b(director|manager|lead|head)\b/i,
  /\b(director|manager|lead|head)\b.*\bit\b/i,
  /\b(engineering|infrastructure|platform|devops|technology)\b.*\b(manager|lead|head|director)\b/i,
  /\bchief\b.*\b(engineer|architect)\b/i,
  /\b(system|network|infrastructure|it)s?\s*(administrator|admin|architect)\b/i,
  /\b(devops|sre|site reliability)\b/i,
];

const DECISION_MAKER = /\b(founder|co-founder|cofounder|ceo|chief executive|owner|president|managing director|proprietor)\b/i;

const RANK_ORDER: ContactRank[] = ["security", "technical", "decision-maker", "other"];

/** One step down the ladder; "other" is the floor. */
function demote(rank: ContactRank): ContactRank {
  const next = RANK_ORDER.indexOf(rank) + 1;
  return RANK_ORDER[Math.min(next, RANK_ORDER.length - 1)];
}

export function rankOrder(rank: ContactRank): number {
  return RANK_ORDER.indexOf(rank);
}

/**
 * Provider seniority, used as a supporting signal only.
 *
 * Hunter's own values are loose — it labels "Sales Executive" and "Director of
 * Legal Affairs" as executive/decision_maker, and files "Principal Engineer"
 * under department "education". So these fields cannot drive the tier on their
 * own; they promote a title that already reads as security, and they break ties
 * within a tier. Department is ignored entirely: it was wrong often enough in
 * sampling that it would cost more than it adds.
 */
export function seniorityWeight(seniority: string | null): number {
  if (seniority === "executive") return 2;
  if (seniority === "senior") return 1;
  return 0;
}

export function classifyContact(candidate: {
  position: string | null;
  seniority?: string | null;
  decisionMaker?: boolean;
}): { rank: ContactRank; reason: string } {
  const { position, seniority = null, decisionMaker = false } = candidate;
  const isExecutive = seniority === "executive";

  if (!position) {
    return decisionMaker
      ? { rank: "decision-maker", reason: "Senior contact, no job title given" }
      : { rank: "other", reason: "No job title available" };
  }

  // A security title only counts as security *leadership* when something backs
  // it up — an explicit leadership word, the CISO/CSO acronym, or the provider
  // placing them at executive level. "Security Analyst" is not the buyer.
  if (SECURITY.test(position)) {
    if (LEADERSHIP.test(position) || /\b(ciso|cso)\b/i.test(position)) {
      return { rank: "security", reason: "Owns security directly" };
    }
    if (isExecutive) {
      return { rank: "security", reason: "Security role at executive level" };
    }
    return { rank: "technical", reason: "Works in security, not leading it" };
  }

  if (TECHNICAL_TITLES.some((pattern) => pattern.test(position))) {
    return { rank: "technical", reason: "Technical leadership" };
  }

  if (DECISION_MAKER.test(position) || decisionMaker) {
    return { rank: "decision-maker", reason: "Decision maker, would forward this on" };
  }

  return { rank: "other", reason: "Not a security or technical owner" };
}

export interface ContactCandidate {
  name: string | null;
  position: string | null;
  email: string;
  confidence: number | null;
  linkedin: string | null;
  seniority: string | null;
  decisionMaker: boolean;
  /**
   * True when the provider suggests the record may be stale or wrong — a failed
   * verification, or low confidence. The spec's rule was "demote if the person
   * is no longer employed there"; Hunter exposes no employment flag, so this is
   * the nearest honest signal it does give.
   */
  unreliable: boolean;
}

export function rankContacts(
  candidates: ContactCandidate[],
  limit = 3
): RankedContact[] {
  const ranked = candidates.map((candidate) => {
    const { rank, reason } = classifyContact(candidate);
    const finalRank = candidate.unreliable ? demote(rank) : rank;
    return {
      name: candidate.name,
      position: candidate.position,
      email: candidate.email,
      rank: finalRank,
      rankReason: candidate.unreliable
        ? `${reason} — demoted, contact details look unreliable`
        : reason,
      confidence: candidate.confidence,
      linkedin: candidate.linkedin,
      downgraded: candidate.unreliable && finalRank !== rank,
      seniority: candidate.seniority,
      decisionMaker: candidate.decisionMaker,
    };
  });

  // Within a tier: seniority, then whether the provider calls them a decision
  // maker, then how sure it is about the address.
  return ranked
    .sort((left, right) => {
      const byRank = rankOrder(left.rank) - rankOrder(right.rank);
      if (byRank !== 0) return byRank;

      const bySeniority =
        seniorityWeight(right.seniority) - seniorityWeight(left.seniority);
      if (bySeniority !== 0) return bySeniority;

      const byDecisionMaker =
        Number(right.decisionMaker) - Number(left.decisionMaker);
      if (byDecisionMaker !== 0) return byDecisionMaker;

      return (right.confidence ?? 0) - (left.confidence ?? 0);
    })
    .slice(0, limit);
}

export const RANK_LABELS: Record<ContactRank, string> = {
  security: "Security leader",
  technical: "Technical leader",
  "decision-maker": "Decision maker",
  other: "Other",
};
