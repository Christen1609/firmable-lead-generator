-- Confirmed-active — a live-threat flag layered above in_kev.
--
-- in_kev means one of the company's CVEs is on the CISA KEV list: the flaw
-- *type* is exploited in the wild. It does not mean this company is being hit.
-- confirmed_active is the stronger, per-company signal: the company's own root
-- domain or a scanned server IP was found in a live threat-intel feed
-- (abuse.ch ThreatFox / URLhaus / Feodo Tracker).
--
-- Two writers, one column (mirrors the one-source-of-truth decision for
-- findings): mark_confirmed_active.py backfills the existing KEV companies from
-- the downloadable feeds, and the live Find More pipeline sets it at ingest for
-- newly resolved KEV companies. It is deliberately gated to in_kev companies —
-- "confirmed active" builds on "actively exploited".
--
-- The signal is time-sensitive (abuse.ch feeds keep a rolling ~6-month window),
-- so active_checked_at records when it was last confirmed and the backfill is
-- meant to be re-run on a schedule. Nothing here is derived by a model.
--
-- Run once in the Supabase SQL editor. Additive and idempotent.

alter table public."Companies"
  add column if not exists confirmed_active  boolean not null default false,
  add column if not exists active_source     text,   -- 'threatfox' | 'urlhaus' | 'feodo'
  add column if not exists active_detail     text,   -- malware family / threat type, for the banner
  add column if not exists active_checked_at timestamptz;

-- Companies already carries a read-only select policy (rls_policies.sql); the
-- new columns inherit it, and writes stay on the server-side service key.

analyze public."Companies";
