export const TIER_PRIORITY: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

export interface TierBadgeStyle {
  background: string;
  color: string;
  border: string;
}

export const TIER_BADGE_STYLES: Record<string, TierBadgeStyle> = {
  Critical: { background: "#b42318", color: "#fff6f4", border: "1px solid #9a1c12" },
  High: { background: "#fce0ca", color: "#8a3010", border: "1px solid #f4c3a1" },
  Medium: { background: "#fbeec2", color: "#79490b", border: "1px solid #efdb9c" },
  Low: { background: "#dcefdd", color: "#1f6530", border: "1px solid #bde0c3" },
};

export const TIER_FILTER_OPTIONS = [
  { value: "all", label: "All tiers" },
  { value: "Critical", label: "Critical" },
  { value: "High", label: "High" },
  { value: "Medium", label: "Medium" },
  { value: "Low", label: "Low" },
] as const;

export const IBM_BREACH_COST_KEY = "ibm_avg_breach";

export const PAGE_SIZE = 10;

export function computeEstimatedExposure(
  maxEpss: number | null,
  ibmBreachCost: number
): number | null {
  if (maxEpss === null) return null;
  return Math.round(ibmBreachCost * maxEpss);
}

export function formatCurrency(value: number): string {
  return "$" + Math.round(value).toLocaleString("en-US");
}

export function formatCurrencyShort(value: number): string {
  if (value >= 1_000_000) {
    return "$" + (value / 1_000_000).toFixed(2).replace(/0$/, "") + "M";
  }
  return "$" + Math.round(value / 1_000) + "k";
}

/** Spelled-out short form for the outreach subject line: "$4.4 million". */
export function formatCurrencyMillions(value: number): string {
  if (value >= 1_000_000) {
    const millions = (value / 1_000_000).toFixed(1).replace(/\.0$/, "");
    return `$${millions} million`;
  }
  return formatCurrency(value);
}

export function formatEpss(epss: number | null): string {
  if (epss === null) return "—";
  return `${Math.round(epss * 100)}%`;
}

export function formatCvss(cvss: number | null): string {
  if (cvss === null) return "—";
  return cvss.toFixed(1) + " / 10";
}

/**
 * Plain-English headline for a finding, derived deterministically from the CVE's
 * own summary text. The brief requires the detail screen to lead with what the
 * flaw lets an attacker do, not with a raw CVE ID — but the scan data carries no
 * title field, only the technical summary. This classifies that summary in code.
 * Nothing here is invented: the summary it was read from is shown directly below.
 */
const VULN_CLASSES: { pattern: RegExp; title: string }[] = [
  { pattern: /remote code execution|code execution|execute arbitrary code|execute untrusted code|arbitrary code|\bRCE\b/i, title: "Attackers can run their own code on this server" },
  { pattern: /command injection|OS command|shell command|arbitrary commands/i, title: "Attackers can run system commands on this server" },
  { pattern: /SQL injection/i, title: "Attackers can reach the database behind this server" },
  { pattern: /server-side request forgery|\bSSRF\b/i, title: "Attackers can make this server call systems behind the firewall" },
  { pattern: /deserializ|unserializ|\bphar\b|stream.wrapper/i, title: "Attackers can smuggle hostile data into the application" },
  { pattern: /overwrite (?:arbitrary )?files|arbitrary file write|write arbitrary/i, title: "Attackers can overwrite files on this server" },
  { pattern: /authentication bypass|bypass authentication|improper authentication|without authentication/i, title: "Attackers can get in without valid credentials" },
  { pattern: /privilege escalation|escalate privileges|gain privileges|elevation of privilege/i, title: "Attackers can raise their own level of access" },
  { pattern: /directory traversal|path traversal/i, title: "Attackers can read files they should never reach" },
  { pattern: /cross-site scripting|\bXSS\b/i, title: "Attackers can hijack a signed-in user's session" },
  { pattern: /cross-site request forgery|\bCSRF\b/i, title: "Attackers can make a signed-in user act without meaning to" },
  { pattern: /buffer overflow|heap overflow|stack overflow|memory corruption|use.after.free|out-of-bounds/i, title: "Attackers can crash or take over the service through memory abuse" },
  { pattern: /open redirect/i, title: "Attackers can bounce your visitors to a site they control" },
  { pattern: /denial of service|\bDoS\b/i, title: "Attackers can knock this service offline" },
  { pattern: /information disclosure|sensitive information|obtain sensitive|read arbitrary files|disclose/i, title: "Attackers can read information that should stay private" },
];

export function describeVulnerability(summary: string | null): string {
  if (!summary) return "A known flaw on an internet-facing service";
  const match = VULN_CLASSES.find((entry) => entry.pattern.test(summary));
  return match ? match.title : "A known flaw on an internet-facing service";
}

export function sortCompaniesByTier<
  T extends { tier: string | null; max_epss: number | null }
>(companies: T[]): T[] {
  return [...companies].sort((leftCompany, rightCompany) => {
    const leftTier = TIER_PRIORITY[leftCompany.tier ?? "Low"] ?? 99;
    const rightTier = TIER_PRIORITY[rightCompany.tier ?? "Low"] ?? 99;
    if (leftTier !== rightTier) return leftTier - rightTier;
    const leftEpss = leftCompany.max_epss ?? 0;
    const rightEpss = rightCompany.max_epss ?? 0;
    return rightEpss - leftEpss;
  });
}
