import { promises as dns } from "node:dns";

/**
 * Live per-company threat checks against abuse.ch ThreatFox — a free feed of
 * live malware / botnet IOCs (IPs and domains).
 *
 * Backs two things: the on-demand "Live threat check" button (a fresh ThreatFox
 * lookup on one company's IP and domain), and the stored `confirmed_active`
 * flag the live pipeline sets at ingest (ThreatFox by domain, gated to in_kev
 * companies). The IP is resolved from the domain at request time, so a match on
 * that IP is labelled as "the address this domain resolves to" rather than
 * asserting anything about a specific server.
 */

const THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/";

export interface ThreatFoxMatch {
  iocValue: string;
  threatType: string | null;
  malware: string | null;
  confidence: number | null;
  firstSeen: string | null;
  lastSeen: string | null;
  reference: string | null;
  /** Whether the company's IP or its domain matched the feed. */
  matchedOn: "ip" | "domain";
}

export interface LiveThreatResult {
  company: string;
  checkedIp: string | null;
  /** True when the feed reports live attack / malware activity. */
  activeAttack: boolean;
  malware: ThreatFoxMatch[];
  /** Human labels of what fired, for the banner. */
  sources: string[];
  checkedAt: string;
  /** Upstreams that failed; surfaced so a partial check is not read as "clean". */
  errors: string[];
}

/** First A record for a domain, or null. Never throws. */
export async function resolveIp(domain: string): Promise<string | null> {
  try {
    const { address } = await dns.lookup(domain);
    return address ?? null;
  } catch {
    return null;
  }
}

interface ThreatFoxRaw {
  ioc?: string;
  threat_type?: string;
  malware_printable?: string;
  malware?: string;
  confidence_level?: number;
  first_seen?: string;
  last_seen?: string;
  reference?: string;
}

/**
 * ThreatFox exact-match IOC search. `exact_match` is deliberately on: a false
 * positive here would put "Confirmed active" on an innocent company, which is
 * worse than missing a subdomain-level IOC.
 */
export async function queryThreatFox(
  term: string,
  authKey: string,
  matchedOn: "ip" | "domain"
): Promise<ThreatFoxMatch[]> {
  const response = await fetch(THREATFOX_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Auth-Key": authKey },
    body: JSON.stringify({
      query: "search_ioc",
      search_term: term,
      exact_match: true,
    }),
  });

  if (!response.ok) {
    throw new Error(`ThreatFox returned ${response.status}`);
  }

  const data = await response.json();
  if (data.query_status !== "ok" || !Array.isArray(data.data)) return [];

  return (data.data as ThreatFoxRaw[]).map((entry) => ({
    iocValue: entry.ioc ?? term,
    threatType: entry.threat_type ?? null,
    malware: entry.malware_printable ?? entry.malware ?? null,
    confidence: entry.confidence_level ?? null,
    firstSeen: entry.first_seen ?? null,
    lastSeen: entry.last_seen ?? null,
    reference: entry.reference ?? null,
    matchedOn,
  }));
}

/**
 * The on-demand deep check for one company: resolve the domain, then run
 * ThreatFox on both the IP and the domain in parallel. One dead upstream never
 * fails the whole check.
 */
export async function checkLiveThreat(
  domain: string,
  authKey: string
): Promise<LiveThreatResult> {
  const checkedIp = await resolveIp(domain);
  const errors: string[] = [];

  const [ipMatches, domainMatches] = await Promise.all([
    checkedIp
      ? queryThreatFox(checkedIp, authKey, "ip").catch((error) => {
          errors.push(errorText("ThreatFox (IP)", error));
          return [] as ThreatFoxMatch[];
        })
      : Promise.resolve([] as ThreatFoxMatch[]),
    queryThreatFox(domain, authKey, "domain").catch((error) => {
      errors.push(errorText("ThreatFox (domain)", error));
      return [] as ThreatFoxMatch[];
    }),
  ]);

  const malware = [...ipMatches, ...domainMatches];

  return {
    company: domain,
    checkedIp,
    activeAttack: malware.length > 0,
    malware,
    sources: malware.length > 0 ? ["abuse.ch ThreatFox"] : [],
    checkedAt: new Date().toISOString(),
    errors,
  };
}

/** The stored flag the live pipeline writes for one KEV company. */
export interface ConfirmedActiveFlag {
  confirmed_active: boolean;
  active_source: string | null;
  active_detail: string | null;
  active_checked_at: string;
}

/**
 * Domain-only ThreatFox check for the ingest path. No IP resolution: the live
 * pipeline already holds the resolved company domain, and a domain match avoids
 * the CDN ambiguity entirely. On any upstream error it returns not-confirmed
 * rather than throwing, so a feed hiccup never fails a pipeline run.
 */
export async function confirmedActiveForDomain(
  domain: string,
  authKey: string
): Promise<ConfirmedActiveFlag> {
  const now = new Date().toISOString();
  try {
    const matches = await queryThreatFox(domain, authKey, "domain");
    if (matches.length === 0) {
      return { confirmed_active: false, active_source: null, active_detail: null, active_checked_at: now };
    }
    const worst = matches[0];
    return {
      confirmed_active: true,
      active_source: "threatfox",
      active_detail: worst.malware ?? worst.threatType ?? "listed in ThreatFox",
      active_checked_at: now,
    };
  } catch {
    return { confirmed_active: false, active_source: null, active_detail: null, active_checked_at: now };
  }
}

function errorText(source: string, error: unknown): string {
  return `${source}: ${error instanceof Error ? error.message : "failed"}`;
}
