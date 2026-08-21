import duckdb
import json
import os
import gzip

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("Loading KEV data...")
with open("kev.json", "r") as f:
    kev_raw = json.load(f)
kev_map = {v["cveID"]: v.get("knownRansomwareCampaignUse", "Unknown") for v in kev_raw["vulnerabilities"]}
print(f"  {len(kev_map)} KEV entries loaded")

print("Querying parquet for rows with vulns...")
con = duckdb.connect()
rows = con.execute("""
  SELECT company, vulns
  FROM 'companies_raw.parquet'
  WHERE vulns IS NOT NULL AND vulns != '' AND vulns != '{}'
""").fetchall()
con.close()
print(f"  {len(rows)} rows with vulns")

print("Extracting per-company CVE data (deduped, top 10 by EPSS)...")
company_vulns = {}

for company, vulns_text in rows:
    if not company:
        continue
    try:
        vulns = json.loads(vulns_text) if isinstance(vulns_text, str) else vulns_text
    except (json.JSONDecodeError, TypeError):
        continue
    if not isinstance(vulns, dict) or not vulns:
        continue

    bucket = company_vulns.setdefault(company, {})

    # A company shows up once per scanned server, so the same CVE arrives many
    # times. Keep whichever copy carries the highest EPSS.
    for cve_id, vdata in vulns.items():
        if cve_id not in bucket or (vdata.get("epss") or 0) > (bucket[cve_id].get("epss") or 0):
            bucket[cve_id] = vdata

output = {}
for company, cve_map in company_vulns.items():
    cve_list = []
    for cve_id, vdata in cve_map.items():
        summary = vdata.get("summary") or ""
        if len(summary) > 300:
            summary = summary[:297] + "..."
        cve_list.append([
            company,
            cve_id,
            vdata.get("cvss"),
            vdata.get("epss"),
            summary,
            cve_id in kev_map,
        ])
    cve_list.sort(key=lambda x: x[3] or 0, reverse=True)
    output[company] = cve_list[:10]

print(f"  {len(output)} companies with vuln data")

# Repo root: this is load_company_vulns.py's input, not a Next.js app asset.
out_path = "company_vulns.json.gz"
json_bytes = json.dumps(output, separators=(",", ":")).encode("utf-8")
with gzip.open(out_path, "wb") as f:
    f.write(json_bytes)

size_mb = os.path.getsize(out_path) / (1024 * 1024)
print(f"  Saved to {out_path} ({size_mb:.1f} MB)")
