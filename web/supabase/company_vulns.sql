-- Company_Vulns — the per-CVE detail table from Backend-architecture.md §4.
--
-- This table was specified in the brief but never created. The live "Find More"
-- pipeline (src/app/api/find-companies/route.ts) upserts into it on every run,
-- so without it every live run silently loses its findings and companies added
-- that way show "No findings yet" on the detail screen.
--
-- Run this once in the Supabase SQL editor.
--
-- Naming note: quoted PascalCase, to match the existing "Companies" table.
-- PostgREST is case-sensitive here — see .matilda/skills/auto-skill-supabase-table-casing.

create table if not exists public."Company_Vulns" (
  company  text    not null references public."Companies"(company) on delete cascade,
  cve_id   text    not null,
  cvss     float8,
  epss     float8,
  summary  text,
  in_kev   boolean not null default false,
  primary key (company, cve_id)
);

-- The detail screen's only access pattern: worst findings for one company.
create index if not exists company_vulns_company_epss_idx
  on public."Company_Vulns" (company, epss desc);

alter table public."Company_Vulns" enable row level security;

-- Read-only for anon/authenticated; writes go through the server-side pipeline
-- route, which uses the secret key and bypasses RLS.
drop policy if exists "Company_Vulns are readable" on public."Company_Vulns";
create policy "Company_Vulns are readable"
  on public."Company_Vulns" for select
  to anon, authenticated
  using (true);
