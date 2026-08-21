"""Backfill the confirmed_active flag on KEV companies from abuse.ch feeds.

Why this exists
---------------
in_kev means a company's CVE is on the CISA KEV list: the flaw *type* is
exploited in the wild. It does not mean this company is being hit. This script
sets the stronger, per-company signal — confirmed_active — by matching each KEV
company's root domain (and, optionally, its scanned server IPs) against
abuse.ch's free, downloadable threat feeds:

  - URLhaus      malware distribution domains / IPs   (host file)
  - ThreatFox    malware C2 / payload delivery IOCs   (host file)
  - Feodo Tracker botnet command-and-control IPs      (IP blocklist)

Feeds are downloaded once and matched locally, so this scales to every KEV
company for free with no per-company API calls. The signal is time-sensitive
(abuse.ch keeps a rolling ~6-month window), so re-run this on a schedule; with
--reset it also clears the flag on KEV companies that no longer match.

Honest expectation: legitimate company domains rarely appear in malware feeds,
so this may flag only a handful — possibly none. That is correct for a claim
this strong. The on-demand "Live threat check" button is the deeper per-company
check.

Prerequisites
-------------
1. web/supabase/confirmed_active.sql has been run (the columns must exist).
2. web/.env.local holds NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_KEY and
   ABUSECH_AUTH_KEY. The write needs the service key (RLS blocks the anon key).

Usage:
    python mark_confirmed_active.py [--dry-run] [--with-ips] [--reset]

Notes
-----
--with-ips additionally matches each company's scanned server IPs, read from
data/companies_raw.parquet via DuckDB, against the IP feeds. It is skipped
automatically if the parquet has no recognisable IP column.
"""
import argparse
import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENV_PATH = os.path.join("web", ".env.local")
PARQUET_PATH = "data/companies_raw.parquet"

# name, kind ('hostfile' | 'iplist'), url, source-key stored in active_source
FEEDS = [
    ("URLhaus", "hostfile", "https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus"),
    ("ThreatFox", "hostfile", "https://threatfox.abuse.ch/downloads/hostfile/", "threatfox"),
    ("Feodo Tracker", "iplist", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "feodo"),
]

# Candidate IP column names in the raw parquet, tried in order.
IP_COLUMNS = ["ip_str", "ip", "ip_address", "ipv4"]


def read_env(path):
    """Minimal .env reader — mirrors load_company_vulns.py, no dependency."""
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def http_get(url, auth_key, timeout=120):
    headers = {"User-Agent": "firmable-lead-generator"}
    if auth_key:
        # abuse.ch moved feed downloads behind an Auth-Key in 2025.
        headers["Auth-Key"] = auth_key
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def registrable_root(host):
    """Registrable domain, so a feed subdomain matches the company root.

    include_psl_private_domains matters here: it treats dynamic-DNS and
    free-subdomain providers (hopto.org, sytes.net, sslip.io, it.com, ...) as
    suffixes, so a malicious `evil.hopto.org` resolves to `evil.hopto.org` and
    does NOT collapse onto — and wrongly flag — the provider `hopto.org`. Those
    providers are thousands of unrelated tenants, not one company.

    Without tldextract we return the host unchanged (exact-match only) rather
    than a naive last-two-labels guess, which would reintroduce those false
    positives."""
    if _extract is not None:
        extracted = _extract(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
    return host.lower()


try:
    from tldextract import TLDExtract  # type: ignore
    _extract = TLDExtract(include_psl_private_domains=True)
except Exception:  # noqa: BLE001 — optional; falls back to exact-match only
    _extract = None


def parse_hostfile(text):
    """Yield hostnames from a hosts-file-format dump (skips comments; a line may
    be "0.0.0.0 domain.com" or a bare domain)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[-1].lower()
        if "." in token and " " not in token and "/" not in token:
            yield token


def parse_iplist(text):
    """Yield IPv4 addresses from a plain IP blocklist (skips comments/headers)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].split()[0]
        try:
            ipaddress.ip_address(token)
            yield token
        except ValueError:
            continue


def download_feeds(auth_key):
    """Returns (domain_source, ip_source): dicts mapping value -> feed source-key."""
    domain_source, ip_source = {}, {}
    for name, kind, url, source in FEEDS:
        try:
            text = http_get(url, auth_key)
        except urllib.error.HTTPError as error:
            print(f"  {name}: HTTP {error.code} — skipped "
                  f"({'needs a valid Auth-Key?' if error.code in (401, 403) else 'unavailable'})")
            continue
        except urllib.error.URLError as error:
            print(f"  {name}: {error.reason} — skipped")
            continue

        if kind == "hostfile":
            count = 0
            for host in parse_hostfile(text):
                domain_source.setdefault(host, source)
                domain_source.setdefault(registrable_root(host), source)
                count += 1
            print(f"  {name}: {count:,} host lines")
        else:
            count = 0
            for ip in parse_iplist(text):
                ip_source.setdefault(ip, source)
                count += 1
            print(f"  {name}: {count:,} IPs")

    return domain_source, ip_source


def fetch_kev_companies(url, key):
    """Every company where in_kev is true, paged past PostgREST's 1000 cap."""
    companies, offset = [], 0
    while True:
        request = urllib.request.Request(
            f"{url}/rest/v1/Companies?select=company&in_kev=is.true",
            headers={
                "apikey": key,
                "Authorization": f"Bearer {key}",
                "Range": f"{offset}-{offset + 999}",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            page = json.loads(response.read().decode("utf-8"))
        if not page:
            break
        companies.extend(row["company"] for row in page)
        if len(page) < 1000:
            break
        offset += 1000
    return companies


def fetch_infrastructure_verdicts(url, key, domains):
    """Which of these domains the project's own classifier already called
    infrastructure. Reused here so a shared provider whose bare domain sits in a
    threat feed (a DDNS/free-subdomain host, not one company) is never flagged
    Confirmed active — no separate blocklist, the pipeline's verdict is enough."""
    infra = set()
    for offset in range(0, len(domains), 100):
        chunk = domains[offset:offset + 100]
        inlist = "(" + ",".join(chunk) + ")"
        target = (
            f"{url}/rest/v1/Domain_Classifications"
            f"?select=domain&verdict=eq.infrastructure"
            f"&domain=in.{urllib.parse.quote(inlist, safe='(),')}"
        )
        request = urllib.request.Request(
            target, headers={"apikey": key, "Authorization": f"Bearer {key}"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            rows = json.loads(response.read().decode("utf-8"))
        infra.update(row["domain"] for row in rows)
    return infra


def load_company_ips(companies):
    """Optional: map company -> set of scanned server IPs, from the raw parquet.
    Returns {} if DuckDB or a usable IP column is unavailable."""
    try:
        import duckdb  # noqa: PLC0415 — only needed for --with-ips
    except ImportError:
        print("  duckdb not installed — skipping IP matching")
        return {}
    if not os.path.exists(PARQUET_PATH):
        print(f"  {PARQUET_PATH} not found — skipping IP matching")
        return {}

    con = duckdb.connect()
    column_names = [row[1] for row in con.execute(
        f"DESCRIBE SELECT * FROM '{PARQUET_PATH}'"
    ).fetchall()]
    ip_column = next((name for name in IP_COLUMNS if name in column_names), None)
    if ip_column is None:
        con.close()
        print(f"  parquet has no IP column ({', '.join(IP_COLUMNS)}) — skipping IP matching")
        return {}

    wanted = set(companies)
    rows = con.execute(
        f"SELECT company, {ip_column} FROM '{PARQUET_PATH}' "
        f"WHERE company IS NOT NULL AND {ip_column} IS NOT NULL"
    ).fetchall()
    con.close()

    company_ips = {}
    for company, ip in rows:
        if company in wanted:
            company_ips.setdefault(company, set()).add(str(ip))
    return company_ips


def patch_company(url, key, company, fields, retries=4):
    payload = json.dumps(fields).encode("utf-8")
    target = f"{url}/rest/v1/Companies?company=eq.{urllib.parse.quote(company, safe='')}"
    request = urllib.request.Request(
        target,
        data=payload,
        method="PATCH",
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        },
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")[:300]
            if error.code not in (429, 500, 502, 503, 504):
                raise SystemExit(f"\nHTTP {error.code} from Supabase on {company}:\n  {body}")
            time.sleep(2 ** attempt)
        except urllib.error.URLError:
            time.sleep(2 ** attempt)
    raise SystemExit(f"PATCH failed after retries for {company}.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Match and report, write nothing.")
    parser.add_argument("--with-ips", action="store_true", help="Also match scanned server IPs from the parquet.")
    parser.add_argument("--reset", action="store_true", help="Clear the flag on KEV companies that no longer match.")
    args = parser.parse_args()

    env = read_env(ENV_PATH)
    url = env.get("NEXT_PUBLIC_SUPABASE_URL")
    key = env.get("SUPABASE_SERVICE_KEY")
    auth_key = env.get("ABUSECH_AUTH_KEY")
    if not url or not key:
        raise SystemExit(f"NEXT_PUBLIC_SUPABASE_URL / SUPABASE_SERVICE_KEY missing from {ENV_PATH}")
    if not auth_key:
        print(f"Note: ABUSECH_AUTH_KEY missing from {ENV_PATH}; feeds that require it will be skipped.")

    print("Downloading abuse.ch feeds...")
    domain_source, ip_source = download_feeds(auth_key)
    print(f"  {len(domain_source):,} feed domains, {len(ip_source):,} feed IPs")
    if not domain_source and not ip_source:
        raise SystemExit("No feed data downloaded — nothing to match against.")

    print("Fetching KEV companies from Supabase...")
    companies = fetch_kev_companies(url, key)
    print(f"  {len(companies):,} companies with in_kev = true")

    company_ips = {}
    if args.with_ips:
        print("Loading scanned server IPs from the parquet...")
        company_ips = load_company_ips(companies)
        print(f"  IPs for {len(company_ips):,} companies")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    matched, cleared = [], []
    for company in companies:
        source = domain_source.get(company.lower())
        detail = None
        if source:
            detail = f"domain listed in {source}"
        elif args.with_ips:
            for ip in company_ips.get(company, ()):
                if ip in ip_source:
                    source = ip_source[ip]
                    detail = f"server IP {ip} listed in {source}"
                    break

        if source:
            matched.append((company, source, detail))
        elif args.reset:
            cleared.append(company)

    # Drop matches the project already classified as infrastructure: a shared
    # DDNS/free-subdomain provider whose bare domain is in a feed is not one
    # company being attacked.
    infra = fetch_infrastructure_verdicts(url, key, [company for company, _, _ in matched])
    excluded = [row for row in matched if row[0] in infra]
    matched = [row for row in matched if row[0] not in infra]
    if excluded:
        print(f"Excluded {len(excluded)} match(es) already classified infrastructure: "
              + ", ".join(company for company, _, _ in excluded))
        if args.reset:
            cleared.extend(company for company, _, _ in excluded)

    print(f"\nMatched {len(matched):,} of {len(companies):,} KEV companies.")
    for company, source, detail in matched[:20]:
        print(f"  + {company}  ({detail})")
    if len(matched) > 20:
        print(f"  ... and {len(matched) - 20:,} more")
    if args.reset:
        print(f"Would clear the flag on {len(cleared):,} no-longer-matching companies.")

    if args.dry_run:
        print("\nDry run — nothing written.")
        return

    print("\nWriting flags to Supabase...")
    for company, source, detail in matched:
        patch_company(url, key, company, {
            "confirmed_active": True,
            "active_source": source,
            "active_detail": detail,
            "active_checked_at": now,
        })
    for company in cleared:
        patch_company(url, key, company, {
            "confirmed_active": False,
            "active_source": None,
            "active_detail": None,
            "active_checked_at": now,
        })

    print(f"Done. Set {len(matched):,}"
          + (f", cleared {len(cleared):,}" if args.reset else "") + ".")


if __name__ == "__main__":
    main()
