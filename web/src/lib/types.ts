export interface Company {
  company: string;
  country: string | null;
  max_cvss: number | null;
  max_epss: number | null;
  cve_count: number | null;
  in_kev: boolean | null;
  ransomware: boolean | null;
  tier: string | null;
  /**
   * Live-threat signal, layered above in_kev. `in_kev` means the flaw type is
   * exploited in the wild; `confirmed_active` means this company's own
   * domain/IP was found in a live attack or malware feed. Set by the abuse.ch
   * backfill and by the live pipeline; null until first checked.
   */
  confirmed_active?: boolean | null;
  active_source?: string | null;
  active_detail?: string | null;
  active_checked_at?: string | null;
}

export interface CompanyVuln {
  company: string;
  cve_id: string;
  cvss: number | null;
  epss: number | null;
  summary: string | null;
  in_kev: boolean | null;
  /** KEV's knownRansomwareCampaignUse for this CVE, joined at read time. */
  ransomware: boolean;
  /**
   * Plain-English headline, already resolved. Regexes first, then the stored
   * Cve_Descriptions label, then the product name, then a generic string —
   * settled once on the server so every consumer shows the same sentence.
   */
  title: string;
  /**
   * Salesperson-readable rewrite of `summary`, from Cve_Plain_Summaries. Null
   * when a CVE has no accepted rewrite yet — the UI shows the raw summary then.
   */
  plain_summary: string | null;
  /** Canned "why the business cares" line for this headline, or null. */
  business_impact: string | null;
}

export interface Setting {
  key: string;
  value: number;
}
