/**
 * abuse.ch ThreatFox lookup for the stored `confirmed_active` flag.
 *
 * The live "Find More" pipeline calls confirmedActiveForDomain() at ingest to
 * flag a KEV company whose domain appears in ThreatFox's live malware / botnet
 * feed. The batch backfill (mark_confirmed_active.py) sets the same flag over
 * the existing companies. Reads only; a feed hiccup never fails a pipeline run.
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

/** The stored flag the live pipeline writes for one KEV company. */
export interface ConfirmedActiveFlag {
  confirmed_active: boolean;
  active_source: string | null;
  active_detail: string | null;
  active_checked_at: string;
}

/**
 * Domain-only ThreatFox check for the ingest path. A domain match avoids the
 * CDN ambiguity of resolving to an IP. On any upstream error it returns
 * not-confirmed rather than throwing, so a feed hiccup never fails a pipeline run.
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
