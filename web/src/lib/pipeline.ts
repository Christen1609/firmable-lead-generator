import { getDomain } from "tldts";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { GEMINI_MODEL } from "@/lib/gemini";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SHODAN_API_BASE = "https://api.shodan.io/shodan/host/search";
const SHODAN_RESULT_LIMIT = 100;

const INFRASTRUCTURE_KEYWORDS = [
  "isp",
  "cloud",
  "hosting",
  "webhost",
  "dns",
  "broadband",
  "telecom",
  "telekom",
  "comunica",
  "provider",
  "backbone",
  "peering",
  "server",
  "servidor",
  "datacenter",
  "datacentre",
  "colo",
  "colocation",
  "vps",
  "fibernet",
  "netcom",
  "aws",
  "azure",
  "amazon",
  "google",
  "digitalocean",
  "linode",
  "ovh",
  "hetzner",
  "vultr",
  "leaseweb",
  "contabo",
];

/** TLDs that only an infrastructure operator registers. */
const INFRASTRUCTURE_TLDS = [".network", ".hosting", ".cloud"];

const SYSTEM_SUFFIXES = [".arpa", "in-addr", "in-addr.arpa"];

/**
 * If the classifier answers for fewer than this share of the domains it was
 * asked about, its whole reply is discarded rather than partially believed.
 */
const MIN_ANSWER_RATE = 0.5;

/**
 * Domains per classifier call. One unbounded prompt containing every ambiguous
 * domain eventually exceeds the context window and truncates, which looks
 * exactly like the model declining to answer.
 */
const CLASSIFIER_CHUNK_SIZE = 40;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ShodanVuln {
  cvss?: number;
  epss?: number;
  summary?: string;
  verified?: boolean;
}

interface ShodanRecord {
  hostnames?: string[];
  /** Shodan nests this under `location` — see Backend-architecture.md §3.1. */
  location?: { country_name?: string };
  /** Kept as a fallback; the search API does not return it at the top level. */
  country_name?: string;
  org?: string;
  isp?: string;
  ssl?: {
    cert?: {
      subject?: { CN?: string };
    };
  };
  vulns?: Record<string, ShodanVuln>;
}

interface KevEntry {
  cveID: string;
  knownRansomwareCampaignUse: string;
}

export interface ProcessedCompany {
  company: string;
  country: string | null;
  max_cvss: number;
  max_epss: number;
  cve_count: number;
  in_kev: boolean;
  ransomware: boolean;
  tier: string;
  /**
   * Live-threat flag, filled in after scoring by the find-companies route for
   * in_kev companies. Defaults false here so every upsert writes the column
   * consistently rather than leaving it to PostgREST's key-union behaviour.
   */
  confirmed_active: boolean;
  active_source: string | null;
  active_detail: string | null;
  active_checked_at: string | null;
}

export interface ProcessedVuln {
  company: string;
  cve_id: string;
  cvss: number | null;
  epss: number | null;
  summary: string | null;
  in_kev: boolean;
}

/**
 * What the model actually said, reconciled against what it was asked.
 *
 * The point of separating `unanswered` from `infrastructure` is that they mean
 * very different things. "The model said infrastructure" is a verdict. "The
 * model did not answer" is missing data, and treating the two the same is how
 * silent loss happens.
 */
export interface DomainResolution {
  asked: number;
  business: Set<string>;
  infrastructure: Set<string>;
  /** Asked about, but no usable verdict came back. Kept, not dropped. */
  unanswered: string[];
  /** True when the reply was too incomplete to trust at all. */
  batchRejected: boolean;
  /** Domains answered from the persisted verdict cache, never sent to the model. */
  cacheHits: number;
}

export interface ResolutionReport {
  asked: number;
  classifiedBusiness: number;
  classifiedInfrastructure: number;
  unanswered: number;
  batchRejected: boolean;
  cacheHits: number;
}

export interface PipelineResult {
  companies: ProcessedCompany[];
  vulns: ProcessedVuln[];
  totalRecordsProcessed: number;
  domainsDropped: number;
  /** Null when no domain was ambiguous enough to need the model. */
  resolution: ResolutionReport | null;
}

// ---------------------------------------------------------------------------
// Layer 1 — Extract root domain
// ---------------------------------------------------------------------------

function extractRootDomain(record: ShodanRecord): string | null {
  const certCommonName = record.ssl?.cert?.subject?.CN;
  if (certCommonName) {
    const cleanedDomain = certCommonName.replace(/^\*\./, "");
    const rootDomain = getDomain(cleanedDomain);
    if (rootDomain) return rootDomain;
  }

  for (const hostname of record.hostnames ?? []) {
    const rootDomain = getDomain(hostname);
    if (rootDomain) return rootDomain;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Layer 2 — Rule-based infrastructure filter (deterministic)
// ---------------------------------------------------------------------------

function isIpAddress(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function isSystemJunk(domain: string): boolean {
  return (
    SYSTEM_SUFFIXES.some((suffix) => domain.endsWith(suffix)) ||
    INFRASTRUCTURE_TLDS.some((tld) => domain.endsWith(tld))
  );
}

function matchesInfrastructureKeywords(domain: string): boolean {
  const domainParts = domain.toLowerCase().split(".");
  return INFRASTRUCTURE_KEYWORDS.some((keyword) =>
    domainParts.some((part) => part.includes(keyword))
  );
}

function isLikelyInfrastructure(domain: string): boolean {
  return (
    isIpAddress(domain) ||
    isSystemJunk(domain) ||
    matchesInfrastructureKeywords(domain)
  );
}

// ---------------------------------------------------------------------------
// Layer 3 — AI resolution for ambiguous domains
// ---------------------------------------------------------------------------

type Verdict = "business" | "infrastructure";

export interface VerdictStore {
  get(domains: string[]): Promise<Map<string, Verdict>>;
  put(entries: { domain: string; verdict: Verdict }[]): Promise<void>;
}

/**
 * Domains with an answer that cannot legitimately change, mixed into every
 * chunk. If the model gets one of these wrong the batch is not trustworthy,
 * regardless of how confident the rest of its answers look. This is the only
 * check that catches a confidently wrong verdict rather than a malformed one.
 */
const CANARIES: { domain: string; expect: Verdict }[] = [
  { domain: "cloudflare.com", expect: "infrastructure" },
  { domain: "bmw.com", expect: "business" },
  { domain: "akamai.com", expect: "infrastructure" },
  { domain: "siemens.com", expect: "business" },
];

function parseVerdicts(
  responseText: string,
  asked: string[]
): Map<string, Verdict> {
  const askedByKey = new Map(asked.map((d) => [d.toLowerCase(), d]));
  const verdicts = new Map<string, Verdict>();

  for (const rawLine of responseText.trim().split("\n")) {
    const line = rawLine.trim().replace(/^\d+[.)]\s*/, "");
    const match = line.match(/^(.+?)\s*[=:]\s*(business|infrastructure)/i);
    if (!match) continue;
    const original = askedByKey.get(match[1].trim().toLowerCase());
    if (!original) continue;
    verdicts.set(original, match[2].toLowerCase() as Verdict);
  }

  return verdicts;
}

async function classifyChunk(
  domains: string[],
  canaries: { domain: string; expect: Verdict }[],
  model: ReturnType<GoogleGenerativeAI["getGenerativeModel"]>
): Promise<{ verdicts: Map<string, Verdict>; trustworthy: boolean }> {
  const submitted = [...domains, ...canaries.map((c) => c.domain)];
  const domainList = submitted
    .map((domain, index) => `${index + 1}. ${domain}`)
    .join("\n");

  const prompt = `You are classifying internet domains. For each domain below, answer with only "business" or "infrastructure".

"business" = a real operating company, organisation, or commercial entity that would buy cybersecurity software.
"infrastructure" = a hosting provider, telecom, ISP, CDN, DNS provider, cloud platform, or other infrastructure service.

Only return the domain name and classification, one per line, in format: domain=classification

Domains:
${domainList}`;

  let verdicts: Map<string, Verdict>;
  try {
    const result = await model.generateContent(prompt);
    verdicts = parseVerdicts(result.response.text(), submitted);
  } catch {
    return { verdicts: new Map(), trustworthy: false };
  }

  for (const canary of canaries) {
    if (verdicts.get(canary.domain) !== canary.expect) {
      return { verdicts: new Map(), trustworthy: false };
    }
    verdicts.delete(canary.domain);
  }

  const answered = domains.filter((d) => verdicts.has(d)).length;
  const trustworthy =
    domains.length === 0 || answered / domains.length >= MIN_ANSWER_RATE;

  return { verdicts, trustworthy: trustworthy };
}

async function resolveAmbiguousDomains(
  domains: string[],
  geminiApiKey: string,
  store?: VerdictStore
): Promise<DomainResolution> {
  const business = new Set<string>();
  const infrastructure = new Set<string>();

  if (domains.length === 0) {
    return { asked: 0, business, infrastructure, unanswered: [], batchRejected: false, cacheHits: 0 };
  }

  
  let toAsk = domains;
  let cacheHits = 0;
  if (store) {
    try {
      const cached = await store.get(domains);
      for (const [domain, verdict] of cached) {
        if (verdict === "business") business.add(domain);
        else infrastructure.add(domain);
      }
      cacheHits = cached.size;
      toAsk = domains.filter((d) => !cached.has(d));
    } catch {
      toAsk = domains;
    }
  }

  const genAI = new GoogleGenerativeAI(geminiApiKey);
  const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

  const fresh: { domain: string; verdict: Verdict }[] = [];
  let anyChunkRejected = false;

 
  for (let i = 0; i < toAsk.length; i += CLASSIFIER_CHUNK_SIZE) {
    const chunk = toAsk.slice(i, i + CLASSIFIER_CHUNK_SIZE);
    const chunkIndex = i / CLASSIFIER_CHUNK_SIZE;
    const canaries = CANARIES.filter((c) => !chunk.includes(c.domain)).slice(
      chunkIndex % 2 === 0 ? 0 : 2,
      chunkIndex % 2 === 0 ? 2 : 4
    );

    const { verdicts, trustworthy } = await classifyChunk(chunk, canaries, model);
    if (!trustworthy) {
      anyChunkRejected = true;
      continue;
    }

    for (const [domain, verdict] of verdicts) {
      if (verdict === "business") business.add(domain);
      else infrastructure.add(domain);
      fresh.push({ domain, verdict });
    }
  }

  if (store && fresh.length > 0) {
    try {
      await store.put(fresh);
    } catch {
      // Persisting is an optimisation; a failure must not lose the verdicts.
    }
  }

  const unanswered = domains.filter(
    (d) => !business.has(d) && !infrastructure.has(d)
  );

  return {
    asked: domains.length,
    business,
    infrastructure,
    unanswered,
    batchRejected: anyChunkRejected,
    cacheHits,
  };
}

// ---------------------------------------------------------------------------
// Stage 3 — Join KEV
// ---------------------------------------------------------------------------

function joinKev(
  cveIds: Iterable<string>,
  kevMap: Map<string, KevEntry>
): { inKev: boolean; ransomware: boolean } {
  let inKev = false;
  let ransomware = false;
  for (const cveId of cveIds) {
    const kevEntry = kevMap.get(cveId);
    if (kevEntry) {
      inKev = true;
      if (kevEntry.knownRansomwareCampaignUse === "Known") {
        ransomware = true;
      }
    }
  }
  return { inKev, ransomware };
}

// ---------------------------------------------------------------------------
// Stage 4 — Score
// ---------------------------------------------------------------------------

function scoreTier(maxEpss: number, inKev: boolean): string {
  if (inKev) return "Critical";
  if (maxEpss >= 0.5) return "High";
  if (maxEpss >= 0.1) return "Medium";
  return "Low";
}

// ---------------------------------------------------------------------------
// KEV map builder
// ---------------------------------------------------------------------------

export function buildKevMap(kevData: {
  vulnerabilities: KevEntry[];
}): Map<string, KevEntry> {
  const kevMap = new Map<string, KevEntry>();
  for (const entry of kevData.vulnerabilities) {
    kevMap.set(entry.cveID, entry);
  }
  return kevMap;
}

// ---------------------------------------------------------------------------
// Shodan API query
// ---------------------------------------------------------------------------

export async function queryShodanApi(
  apiKey: string,
  target: { country?: string; product?: string }
): Promise<ShodanRecord[]> {
  const queryParts: string[] = [];
  if (target.country) {
    queryParts.push(`country:${target.country}`);
  }
  if (target.product) {
    queryParts.push(`product:${target.product}`);
  }
  if (queryParts.length === 0) {
    throw new Error("At least one of country or product must be provided");
  }

  const searchQuery = queryParts.join(" ");
  const params = new URLSearchParams({
    key: apiKey,
    query: searchQuery,
    limit: String(SHODAN_RESULT_LIMIT),
  });

  const apiUrl = `${SHODAN_API_BASE}?${params.toString()}`;
  const response = await fetch(apiUrl);

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Shodan API returned ${response.status}: ${errorBody.slice(0, 200)}`
    );
  }

  const data = await response.json();
  return (data.matches ?? []) as ShodanRecord[];
}

// ---------------------------------------------------------------------------
// Full pipeline
// ---------------------------------------------------------------------------

export async function runPipeline(
  records: ShodanRecord[],
  kevMap: Map<string, KevEntry>,
  geminiApiKey: string,
  verdictStore?: VerdictStore
): Promise<PipelineResult> {
  // Layer 1 + Layer 2: extract and filter domains
  const domainToRecords = new Map<string, ShodanRecord[]>();
  let domainsDropped = 0;

  for (const record of records) {
    const rootDomain = extractRootDomain(record);
    if (!rootDomain) {
      domainsDropped++;
      continue;
    }
    if (isLikelyInfrastructure(rootDomain)) {
      domainsDropped++;
      continue;
    }

    const existing = domainToRecords.get(rootDomain);
    if (existing) {
      existing.push(record);
    } else {
      domainToRecords.set(rootDomain, [record]);
    }
  }

  
  const ambiguousDomains = [...domainToRecords.keys()];


  let resolutionReport: ResolutionReport | null = null;
  if (ambiguousDomains.length > 0 && geminiApiKey) {
    const resolution = await resolveAmbiguousDomains(
      ambiguousDomains,
      geminiApiKey,
      verdictStore
    );

    for (const domain of resolution.infrastructure) {
      domainToRecords.delete(domain);
      domainsDropped++;
    }

    if (resolution.unanswered.length > 0) {
      console.warn(
        `Domain classifier: ${resolution.unanswered.length} of ${resolution.asked} ` +
          `domains unanswered${resolution.batchRejected ? " (batch rejected)" : ""}, kept: ` +
          resolution.unanswered.slice(0, 20).join(", ")
      );
    }

    resolutionReport = {
      asked: resolution.asked,
      classifiedBusiness: resolution.business.size,
      classifiedInfrastructure: resolution.infrastructure.size,
      unanswered: resolution.unanswered.length,
      batchRejected: resolution.batchRejected,
      cacheHits: resolution.cacheHits,
    };
  }

  // Stages 3–5: join KEV, score, aggregate
  const companyMap = new Map<string, ProcessedCompany>();
  const vulnMap = new Map<string, ProcessedVuln>();

  for (const [domain, domainRecords] of domainToRecords) {
    let maxCvss = 0;
    let maxEpss = 0;
    let country: string | null = null;
    
    const distinctCveIds = new Set<string>();

    for (const record of domainRecords) {
      const recordCountry = record.location?.country_name ?? record.country_name;
      if (!country && recordCountry) {
        country = recordCountry;
      }

      const recordVulns = record.vulns ?? {};

      for (const cveId of Object.keys(recordVulns)) {
        distinctCveIds.add(cveId);

        const vulnData = recordVulns[cveId];
        const cvss = vulnData.cvss ?? 0;
        const epss = vulnData.epss ?? 0;
        maxCvss = Math.max(maxCvss, cvss);
        maxEpss = Math.max(maxEpss, epss);

        const vulnKey = `${domain}-${cveId}`;
        if (!vulnMap.has(vulnKey)) {
          const kevEntry = kevMap.get(cveId);
          vulnMap.set(vulnKey, {
            company: domain,
            cve_id: cveId,
            cvss: vulnData.cvss ?? null,
            epss: vulnData.epss ?? null,
            summary: vulnData.summary ?? null,
            in_kev: !!kevEntry,
          });
        }
      }
    }

    if (distinctCveIds.size === 0) continue;

    const { inKev, ransomware } = joinKev(distinctCveIds, kevMap);
    const tier = scoreTier(maxEpss, inKev);

    companyMap.set(domain, {
      company: domain,
      country,
      max_cvss: maxCvss,
      max_epss: maxEpss,
      cve_count: distinctCveIds.size,
      in_kev: inKev,
      ransomware,
      tier,
      confirmed_active: false,
      active_source: null,
      active_detail: null,
      active_checked_at: null,
    });
  }

  return {
    companies: Array.from(companyMap.values()),
    vulns: Array.from(vulnMap.values()),
    totalRecordsProcessed: records.length,
    domainsDropped,
    resolution: resolutionReport,
  };
}
