"""How many per-CVE rows exist in the batch data at various per-company caps.

extract_vulns.py keeps only the top 10 CVEs per company. This measures what that
discards, so the cap for the Supabase Company_Vulns load is a decision made on
numbers rather than a guess.
"""
import duckdb
import json
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

print("Querying parquet...")
con = duckdb.connect()
rows = con.execute("""
  SELECT company, vulns
  FROM 'companies_raw.parquet'
  WHERE vulns IS NOT NULL AND vulns != '' AND vulns != '{}'
""").fetchall()
con.close()
print(f"  {len(rows)} rows with vulns")

company_cves = {}
for company, vulns_text in rows:
    if not company:
        continue
    try:
        vulns = json.loads(vulns_text) if isinstance(vulns_text, str) else vulns_text
    except (json.JSONDecodeError, TypeError):
        continue
    if not isinstance(vulns, dict) or not vulns:
        continue
    company_cves.setdefault(company, set()).update(vulns.keys())

counts = sorted((len(v) for v in company_cves.values()), reverse=True)
total = sum(counts)
print(f"\ncompanies with vulns : {len(counts)}")
print(f"uncapped total rows  : {total:,}")
print(f"largest company      : {counts[0]:,} CVEs")
print(f"median               : {counts[len(counts) // 2]}")

for cap in (10, 25, 50, 100, 250):
    capped = sum(min(c, cap) for c in counts)
    pct = 100 * capped / total
    over = sum(1 for c in counts if c > cap)
    print(f"cap {cap:>4}: {capped:>10,} rows  ({pct:5.1f}% of all)  "
          f"{over:,} companies truncated")
