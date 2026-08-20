-- Header aggregates for the prospect list — filter-aware.
--
-- The list header shows four numbers and a "signal mix" of the top exposure
-- types, all recomputed for the current tier / country / search filters. Plain
-- PostgREST cannot SUM or bucket, so both are SQL functions that take the same
-- three filters getCompaniesPage() uses and are read with a single .rpc() call.
--
-- SECURITY INVOKER (the default): RLS still applies, and anon already has a
-- read policy on both tables, so no data escapes that the list itself couldn't
-- already show. The dollar figure is NOT computed here — this returns the sum of
-- max_epss and the app multiplies by the IBM breach constant, keeping the
-- "every figure computed in code" guarantee intact.
--
-- The signal mix reads a precomputed `category` column rather than regex-scanning
-- 182k findings per request (that scan blew the anon statement timeout). The
-- CASE mirrors the first-match order of describeVulnerability() in
-- src/lib/constants.ts, so the bars agree with the detail page's labels.
--
-- Run once in the Supabase SQL editor. Safe to re-run (idempotent) — the UPDATE
-- reclassifies every row, so it also refreshes after a new pipeline load.

-- ---------------------------------------------------------------------------
-- Precomputed finding category
-- ---------------------------------------------------------------------------
alter table public."Company_Vulns" add column if not exists category text;

update public."Company_Vulns" set category = case
  when summary ~* 'remote code execution|execute arbitrary code|arbitrary code|\yRCE\y|command injection|OS command' then 'Remote code execution'
  when summary ~* 'denial of service|\yDoS\y' then 'Denial of service'
  when summary ~* 'buffer overflow|heap overflow|stack overflow|memory corruption|use.after.free|out-of-bounds' then 'Memory corruption'
  when summary ~* 'cross-site scripting|\yXSS\y' then 'Cross-site scripting'
  when summary ~* 'server-side request forgery|\ySSRF\y' then 'Server-side request forgery'
  when summary ~* 'sql injection' then 'SQL injection'
  when summary ~* 'authentication bypass|bypass authentication|improper authentication|without authentication' then 'Authentication bypass'
  when summary ~* 'privilege escalation|escalate privileges|elevation of privilege' then 'Privilege escalation'
  when summary ~* 'directory traversal|path traversal' then 'Path traversal'
  when summary ~* 'information disclosure|sensitive information|obtain sensitive|read arbitrary files' then 'Information disclosure'
  else 'Other'
end;

create index if not exists company_vulns_category_idx on public."Company_Vulns" (category);

-- Materialized unfiltered signal mix. Grouping 182k findings live blows the
-- anon statement timeout on the free tier, and the unfiltered view is both the
-- most common and the heaviest, so it is precomputed into a tiny table here and
-- refreshed on every re-run. Filtered views are smaller subsets and stay live.
create table if not exists public.signal_mix_stats (
  category text primary key,
  findings bigint not null
);
alter table public.signal_mix_stats enable row level security;
drop policy if exists "signal_mix_stats readable" on public.signal_mix_stats;
create policy "signal_mix_stats readable"
  on public.signal_mix_stats for select to anon, authenticated using (true);
truncate public.signal_mix_stats;
insert into public.signal_mix_stats (category, findings)
  select category, count(*)::bigint
  from public."Company_Vulns"
  where category is not null and category <> 'Other'
  group by category;

-- A filtered signal mix does a live join; give anon headroom over the 3s default.
alter role anon set statement_timeout = '10s';
alter role authenticated set statement_timeout = '10s';

-- ---------------------------------------------------------------------------
-- Aggregate functions
-- ---------------------------------------------------------------------------
create or replace function public.get_company_stats(
  p_tier text, p_country text, p_search text
)
returns table(total bigint, kev_count bigint, active_count bigint, epss_sum double precision)
language sql
stable
as $$
  select
    count(*)::bigint,
    count(*) filter (where in_kev)::bigint,
    count(*) filter (where confirmed_active)::bigint,
    coalesce(sum(max_epss), 0)::double precision
  from public."Companies"
  where (p_tier = 'all' or tier = p_tier)
    and (p_country = 'all' or country = p_country)
    and (p_search = '' or company ilike '%' || p_search || '%');
$$;

-- Unfiltered is the common (and heaviest) view, so it skips the join to
-- Companies entirely and just groups the precomputed category. A filtered view
-- is a smaller subset, driven by the Companies index, so its join is cheap.
create or replace function public.get_signal_mix(
  p_tier text, p_country text, p_search text
)
returns table(category text, findings bigint)
language plpgsql
stable
as $$
begin
  if p_tier = 'all' and p_country = 'all' and coalesce(p_search, '') = '' then
    return query
      select s.category, s.findings
      from public.signal_mix_stats s
      order by s.findings desc
      limit 4;
  else
    return query
      select v.category, count(*)::bigint
      from public."Company_Vulns" v
      join public."Companies" c on c.company = v.company
      where v.category is not null and v.category <> 'Other'
        and (p_tier = 'all' or c.tier = p_tier)
        and (p_country = 'all' or c.country = p_country)
        and (p_search = '' or c.company ilike '%' || p_search || '%')
      group by v.category
      order by 2 desc
      limit 4;
  end if;
end;
$$;

grant execute on function public.get_company_stats(text, text, text) to anon, authenticated;
grant execute on function public.get_signal_mix(text, text, text) to anon, authenticated;
