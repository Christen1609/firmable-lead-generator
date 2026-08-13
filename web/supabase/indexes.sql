create extension if not exists pg_trgm;

create index if not exists companies_epss_company_idx
  on public."Companies" (max_epss desc, company desc);

create index if not exists companies_tier_epss_company_idx
  on public."Companies" (tier, max_epss desc, company desc);

create index if not exists companies_country_epss_company_idx
  on public."Companies" (country, max_epss desc, company desc);

create index if not exists companies_company_trgm_idx
  on public."Companies" using gin (company gin_trgm_ops);

drop index if exists companies_tier_epss_idx;

analyze public."Companies";
