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


/** Compact form for large book-wide totals: $76.9B, $8.6B, $420M, $12k. */
export function formatCompactCurrency(value: number): string {
  if (value >= 1_000_000_000) return "$" + (value / 1_000_000_000).toFixed(1).replace(/\.0$/, "") + "B";
  if (value >= 1_000_000) return "$" + (value / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
  if (value >= 1_000) return "$" + Math.round(value / 1_000) + "k";
  return "$" + Math.round(value);
}

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


export const VULN_TITLES: Record<string, string> = {
  RCE: "Attackers can run their own code on this server",
  CMD: "Attackers can run system commands on this server",
  SQLI: "Attackers can reach the database behind this server",
  SSRF: "Attackers can make this server call systems behind the firewall",
  DESER: "Attackers can smuggle hostile data into the application",
  FILEWRITE: "Attackers can overwrite files on this server",
  AUTHBYPASS: "Attackers can get in without valid credentials",
  PRIVESC: "Attackers can raise their own level of access",
  TRAVERSAL: "Attackers can read files they should never reach",
  XSS: "Attackers can hijack a signed-in user's session",
  CSRF: "Attackers can make a signed-in user act without meaning to",
  MEMORY: "Attackers can crash or take over the service through memory abuse",
  REDIRECT: "Attackers can bounce your visitors to a site they control",
  DOS: "Attackers can knock this service offline",
  INFO: "Attackers can read information that should stay private",
  SMUGGLING: "Attackers can sneak hidden requests past your defences",
  SPOOF: "Attackers can impersonate a trusted source",
  SESSION: "Attackers can take over a signed-in session",
  XXE: "Attackers can make this server fetch files and internal systems",
  RACE: "Attackers can exploit a timing flaw to slip past a check",
  CREDS: "Attackers can log in with credentials shipped in the product",
  ACCESS: "Attackers can reach data or actions without permission",
  VALIDATION: "Attackers can feed this server input it fails to check",
  ENUM: "Attackers can work out which accounts exist",
  MITM: "Attackers positioned on the network can read or alter traffic",
};


const KNOWN_PRODUCTS: [RegExp, string][] = [
  [/Apache HTTP Server|\bhttpd\b|mod_(?:proxy|ssl|rewrite|lua|http2)/i, "Apache HTTP Server"],
  [/\bOpenSSH\b|\bsshd\b/i, "OpenSSH"],
  [/\bOpenSSL\b/i, "OpenSSL"],
  [/\bnginx\b/i, "nginx"],
  [/\bPHP\b/i, "PHP"],
  [/\bMySQL\b|\bMariaDB\b/i, "MySQL"],
  [/\bPostgreSQL\b/i, "PostgreSQL"],
  [/\bExim\b/i, "Exim"],
  [/\bPostfix\b/i, "Postfix"],
  [/\bDovecot\b/i, "Dovecot"],
  [/\bWordPress\b/i, "WordPress"],
  [/\bTomcat\b/i, "Apache Tomcat"],
  [/\bIIS\b|Internet Information Services/i, "Microsoft IIS"],
  [/\bProFTPD\b|\bvsftpd\b|\bFTP server\b/i, "the FTP server"],
  [/\bSamba\b/i, "Samba"],
  [/\bBIND\b|\bnamed\b/i, "BIND"],
];

const GENERIC_DESCRIPTION = "A known flaw on an internet-facing service";


function describeByProduct(summary: string): string | null {
  const match = KNOWN_PRODUCTS.find(([pattern]) => pattern.test(summary));
  return match ? `A known flaw in ${match[1]}` : null;
}


export function describeVulnerability(
  summary: string | null,
  label?: string | null
): string {
  if (summary) {
    const match = VULN_CLASSES.find((entry) => entry.pattern.test(summary));
    if (match) return match.title;
  }

  if (label && VULN_TITLES[label]) return VULN_TITLES[label];

  if (summary) {
    const byProduct = describeByProduct(summary);
    if (byProduct) return byProduct;
  }

  return GENERIC_DESCRIPTION;
}


const BUSINESS_IMPACT: Record<string, string> = {
  "Attackers can run their own code on this server":
    "They could take full control of the machine — installing malware, stealing data, or reaching the rest of the network.",
  "Attackers can run system commands on this server":
    "They could run commands as if they were staff, opening the door to data theft.",
  "Attackers can reach the database behind this server":
    "Customer and business records could be read, changed, or stolen.",
  "Attackers can make this server call systems behind the firewall":
    "Internal systems never meant to face the internet could be reached.",
  "Attackers can smuggle hostile data into the application":
    "The application could be tricked into trusting attacker-supplied data.",
  "Attackers can overwrite files on this server":
    "Files on the server, including the website itself, could be changed or replaced.",
  "Attackers can get in without valid credentials":
    "Someone could get in without a valid login.",
  "Attackers can raise their own level of access":
    "A small foothold could be turned into full administrative control.",
  "Attackers can read files they should never reach":
    "Private files on the server could be read by outsiders.",
  "Attackers can hijack a signed-in user's session":
    "A logged-in user's account could be hijacked in their browser.",
  "Attackers can make a signed-in user act without meaning to":
    "A logged-in user could be tricked into actions they never intended.",
  "Attackers can crash or take over the service through memory abuse":
    "The service could be crashed or taken over through low-level memory abuse.",
  "Attackers can bounce your visitors to a site they control":
    "Your visitors could be quietly sent to a scam or malware site.",
  "Attackers can knock this service offline":
    "The service could be taken offline, cutting off customers and revenue.",
  "Attackers can read information that should stay private":
    "Information that should stay private could be exposed to outsiders.",
  "Attackers can sneak hidden requests past your defences":
    "Hidden malicious requests could slip past your defences.",
  "Attackers can impersonate a trusted source":
    "An attacker could pose as a trusted source to fool users or systems.",
  "Attackers can take over a signed-in session":
    "An active user's session could be taken over.",
  "Attackers can make this server fetch files and internal systems":
    "The server could be tricked into fetching internal files and systems.",
  "Attackers can exploit a timing flaw to slip past a check":
    "A timing trick could let an attacker slip past a security check.",
  "Attackers can log in with credentials shipped in the product":
    "Built-in default passwords could let an attacker simply log in.",
  "Attackers can reach data or actions without permission":
    "Data or actions could be reached without the right permission.",
  "Attackers can feed this server input it fails to check":
    "The server could be fed input it fails to check, with unpredictable results.",
  "Attackers can work out which accounts exist":
    "An attacker could map which accounts exist, helping further attacks.",
  "Attackers positioned on the network can read or alter traffic":
    "Someone on the network could read or tamper with the traffic.",
};


export function businessImpact(title: string): string | null {
  return BUSINESS_IMPACT[title] ?? null;
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
