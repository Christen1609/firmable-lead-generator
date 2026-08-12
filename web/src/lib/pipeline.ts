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
  "dns",
  "broadband",
  "telecom",
  "server",
  "datacenter",
  "colo",
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

const SYSTEM_SUFFIXES = [".arpa", "in-addr", "in-addr.arpa"];

const MAX_DOMAIN_SERVER_COUNT = 50;

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
}

export interface ProcessedVuln {
  company: string;
  cve_id: string;
  cvss: number | null;
  epss: number | null;
  summary: string | null;
  in_kev: boolean;
}

export interface PipelineResult {
  companies: ProcessedCompany[];
  vulns: ProcessedVuln[];
  totalRecordsProcessed: number;
  domainsDropped: number;
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

  if (record.hostnames && record.hostnames.length > 0) {
    for (const hostname of record.hostnames) {
      const rootDomain = getDomain(hostname);
      if (rootDomain) return rootDomain;
    }
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
  return SYSTEM_SUFFIXES.some((suffix) => domain.endsWith(suffix));
}

function matchesInfrastructureKeywords(domain: string): boolean {
  const domainParts = domain.toLowerCase().split(".");
  return INFRASTRUCTURE_KEYWORDS.some((keyword) =>
    domainParts.some((part) => part.includes(keyword))
  );
}

function isLikelyInfrastructure(domain: string): boolean {
  if (isIpAddress(domain)) return true;
  if (isSystemJunk(domain)) return true;
  if (matchesInfrastructureKeywords(domain)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Layer 3 — AI resolution for ambiguous domains
// ---------------------------------------------------------------------------

async function resolveAmbiguousDomains(
  domains: string[],
  geminiApiKey: string
): Promise<Set<string>> {
  if (domains.length === 0) return new Set();

  const genAI = new GoogleGenerativeAI(geminiApiKey);
  const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

  const domainList = domains.map((domain, index) => `${index + 1}. ${domain}`).join("\n");

  const prompt = `You are classifying internet domains. For each domain below, answer with only "business" or "infrastructure".

"business" = a real operating company, organisation, or commercial entity that would buy cybersecurity software.
"infrastructure" = a hosting provider, telecom, ISP, CDN, DNS provider, cloud platform, or other infrastructure service.

Only return the domain name and classification, one per line, in format: domain=classification

Domains:
${domainList}`;

  try {
    const result = await model.generateContent(prompt);
    const responseText = result.response.text();

    const businessDomains = new Set<string>();
    const lines = responseText.trim().split("\n");
    for (const line of lines) {
      const [domain, classification] = line.split("=").map((part) => part.trim());
      if (domain && classification === "business") {
        businessDomains.add(domain);
      }
    }
    return businessDomains;
  } catch {
    // If AI fails, keep all ambiguous domains (err on the side of inclusion)
    return new Set(domains);
  }
}

// ---------------------------------------------------------------------------
// Stage 3 — Join KEV
// ---------------------------------------------------------------------------

function joinKev(
  cveIds: string[],
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
  geminiApiKey: string
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

  // Layer 2 continued: drop domains with implausibly high server counts
  const ambiguousDomains: string[] = [];
  for (const [domain, domainRecords] of domainToRecords) {
    if (domainRecords.length > MAX_DOMAIN_SERVER_COUNT) {
      ambiguousDomains.push(domain);
    }
  }

  // Layer 3: AI resolution for ambiguous domains
  if (ambiguousDomains.length > 0 && geminiApiKey) {
    const businessDomains = await resolveAmbiguousDomains(
      ambiguousDomains,
      geminiApiKey
    );
    for (const domain of ambiguousDomains) {
      if (!businessDomains.has(domain)) {
        domainToRecords.delete(domain);
        domainsDropped++;
      }
    }
  }

  // Stages 3–5: join KEV, score, aggregate
  const companyMap = new Map<string, ProcessedCompany>();
  const vulnMap = new Map<string, ProcessedVuln>();

  for (const [domain, domainRecords] of domainToRecords) {
    let maxCvss = 0;
    let maxEpss = 0;
    let allCveIds: string[] = [];
    let country: string | null = null;

    for (const record of domainRecords) {
      const recordCountry = record.location?.country_name ?? record.country_name;
      if (!country && recordCountry) {
        country = recordCountry;
      }

      const recordVulns = record.vulns ?? {};
      const cveIds = Object.keys(recordVulns);
      allCveIds = allCveIds.concat(cveIds);

      for (const cveId of cveIds) {
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

    if (allCveIds.length === 0) continue;

    const distinctCveIds = [...new Set(allCveIds)];
    const { inKev, ransomware } = joinKev(distinctCveIds, kevMap);
    const tier = scoreTier(maxEpss, inKev);

    companyMap.set(domain, {
      company: domain,
      country,
      max_cvss: maxCvss,
      max_epss: maxEpss,
      cve_count: distinctCveIds.length,
      in_kev: inKev,
      ransomware,
      tier,
    });
  }

  return {
    companies: Array.from(companyMap.values()),
    vulns: Array.from(vulnMap.values()),
    totalRecordsProcessed: records.length,
    domainsDropped,
  };
}
