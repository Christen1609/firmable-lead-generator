import { cacheTag, cacheLife } from "next/cache";
import { supabasePublic } from "@/lib/supabase-public";
import { CACHE_TAGS } from "@/lib/queries";
import { describeVulnerability, businessImpact } from "@/lib/constants";
import kevData from "@/data/kev.json";
import type { CompanyVuln } from "@/lib/types";

/** Matches the per-company cap applied by the batch load. */
const MAX_FINDINGS_SHOWN = 10;

/** CVE ID -> whether CISA links it to a known ransomware campaign. */
let cachedRansomware: Set<string> | null = null;

function loadRansomwareCves(): Set<string> {
  if (cachedRansomware) return cachedRansomware;

  const entries = (kevData as {
    vulnerabilities: { cveID: string; knownRansomwareCampaignUse?: string }[];
  }).vulnerabilities;

  const ransomwareCves = new Set<string>();
  for (const entry of entries) {
    if (entry.knownRansomwareCampaignUse === "Known") {
      ransomwareCves.add(entry.cveID);
    }
  }

  cachedRansomware = ransomwareCves;
  return ransomwareCves;
}

/**
 * Worst findings for one company, straight from Supabase.
 *
 * Company_Vulns is the single source of truth, per Backend-architecture.md §4.
 * The batch pass over the 5 GB scan file (load_company_vulns.py) and the live
 * "Find More" pipeline both write to it, so a company's findings do not depend
 * on how it entered the table.
 *
 * This previously merged in a gzipped copy of the batch findings bundled into
 * the app, which meant existing companies and pipeline-added ones were served
 * from different places. That file is now only the loader's input and lives at
 * the repo root, out of the deployment.
 *
 * Ordering and the cap are done in the query so Postgres uses the
 * (company, epss desc) index rather than shipping every row to the app.
 *
 * Cached per company. This was previously the one uncached query on the detail
 * page, which made caching the other two pointless: all three run under one
 * Promise.all, so the page waits for the slowest, and an uncached query held
 * the floor no matter how fast its siblings returned. Caching it is what lets
 * a repeat view reach Postgres zero times.
 *
 * The objection to caching it was that 25,000+ companies would rarely repeat.
 * That argument reads the access pattern backwards — nobody browses 25,000
 * companies, they open the top of a ranked list over and over, so the entries
 * that exist are exactly the ones asked for again.
 *
 * Tagged with the same key the pipeline purges, so a live run makes new
 * findings visible immediately rather than when the TTL lapses.
 */
export async function getCompanyVulns(
  companyName: string
): Promise<CompanyVuln[]> {
  "use cache";
  cacheTag(CACHE_TAGS.companies);
  cacheLife("minutes");

  const { data, error } = await supabasePublic
    .from("Company_Vulns")
    .select("company,cve_id,cvss,epss,summary,in_kev")
    .eq("company", companyName)
    .order("epss", { ascending: false })
    .limit(MAX_FINDINGS_SHOWN);

  if (error) {
    console.error(
      `Company_Vulns lookup failed for ${companyName}: ${error.message}`
    );
    return [];
  }

  const findings = data ?? [];

  // Per-CVE enrichment for the ten rows on screen: the model-assigned label (for
  // CVEs the regexes cannot classify) and the plain-English rewrite. One table,
  // one round trip, allowed to fail — describeVulnerability falls back to the
  // regexes and the card falls back to the raw summary on an empty map.
  const labels = new Map<string, string>();
  const plainSummaries = new Map<string, string>();
  const { data: enrichRows } = await supabasePublic
    .from("Cve_Enrichment")
    .select("cve_id,label,plain_summary")
    .in("cve_id", findings.map((vuln) => vuln.cve_id));

  for (const row of enrichRows ?? []) {
    if (row.label) labels.set(row.cve_id as string, row.label as string);
    if (row.plain_summary) plainSummaries.set(row.cve_id as string, row.plain_summary as string);
  }

  const ransomwareCves = loadRansomwareCves();
  return findings.map((vuln) => {
    const title = describeVulnerability(vuln.summary, labels.get(vuln.cve_id));
    return {
      ...vuln,
      ransomware: ransomwareCves.has(vuln.cve_id),
      title,
      plain_summary: plainSummaries.get(vuln.cve_id) ?? null,
      business_impact: businessImpact(title),
    };
  });
}
