export interface Company {
  company: string;
  country: string | null;
  max_cvss: number | null;
  max_epss: number | null;
  cve_count: number | null;
  in_kev: boolean | null;
  ransomware: boolean | null;
  tier: string | null;
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
}

export interface Setting {
  key: string;
  value: number;
}
