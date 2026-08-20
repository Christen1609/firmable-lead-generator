import { NextRequest, NextResponse } from "next/server";
import { checkLiveThreat, type LiveThreatResult } from "@/lib/live-threat";
import { rateLimit, clientIp } from "@/lib/rate-limit";

/**
 * On-demand live threat check for one company.
 *
 * Runs abuse.ch ThreatFox (is this IP/domain in a live malware feed) for one
 * company. Read-only, nothing persisted — the stored `confirmed_active` flag is
 * set by the pipeline and the backfill, not here. Results are cached per company
 * so repeated clicks during a demo don't re-hit the feed.
 */

const LIVE_THREAT_LIMIT = 10;
const LIVE_THREAT_WINDOW_MS = 60_000;
const CACHE_TTL_MS = 12 * 60 * 60 * 1000;

interface CacheEntry {
  result: LiveThreatResult;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();

function evictExpired(now: number): void {
  for (const [key, entry] of cache) {
    if (entry.expiresAt <= now) cache.delete(key);
  }
}

const DOMAIN_PATTERN = /^[A-Za-z0-9.-]{1,253}$/;

export async function POST(request: NextRequest) {
  const limit = rateLimit(
    `livethreat:${clientIp(request)}`,
    LIVE_THREAT_LIMIT,
    LIVE_THREAT_WINDOW_MS
  );
  if (!limit.allowed) {
    return NextResponse.json(
      { error: `Too many checks. Try again in ${limit.retryAfterSeconds}s.` },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSeconds) } }
    );
  }

  const abusechKey = process.env.ABUSECH_AUTH_KEY;
  if (!abusechKey) {
    return NextResponse.json(
      { error: "abuse.ch key is not configured. Set ABUSECH_AUTH_KEY in .env.local" },
      { status: 500 }
    );
  }

  const body: { company?: string } = await request.json();
  const domain = body.company?.trim().toLowerCase();
  if (!domain || !DOMAIN_PATTERN.test(domain)) {
    return NextResponse.json({ error: "A valid company domain is required" }, { status: 400 });
  }

  const now = Date.now();
  const cached = cache.get(domain);
  if (cached && cached.expiresAt > now) {
    return NextResponse.json({ ...cached.result, cached: true });
  }

  try {
    const result = await checkLiveThreat(domain, abusechKey);

    if (cache.size > 500) evictExpired(now);
    cache.set(domain, { result, expiresAt: now + CACHE_TTL_MS });

    return NextResponse.json({ ...result, cached: false });
  } catch (error) {
    // Fail soft: a check that could not complete must read as "couldn't check",
    // never as a crash and never as a clean bill of health.
    const message = error instanceof Error ? error.message : "Failed to check";
    return NextResponse.json(
      { company: domain, activeAttack: false, error: message },
      { status: 502 }
    );
  }
}
