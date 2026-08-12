import { supabase } from "@/lib/supabase";
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
 */
export async function getCompanyVulns(
  companyName: string
): Promise<CompanyVuln[]> {
  const { data, error } = await supabase
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

  const ransomwareCves = loadRansomwareCves();
  return (data ?? []).map((vuln) => ({
    ...vuln,
    ransomware: ransomwareCves.has(vuln.cve_id),
  }));
}
