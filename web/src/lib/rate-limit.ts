import type { NextRequest } from "next/server";

/**
 * Per-IP rate limiting for the routes that spend money.
 *
 * These three routes are called from the browser, so they cannot be gated
 * behind a shared secret — anything the client can send, an attacker can read
 * out of the bundle and replay. Without a login there is no caller identity to
 * check, so the practical control is throughput per source address.
 *
 * Honest limitation: this counter lives in the memory of one serverless
 * instance. Vercel may run several concurrently and recycles them freely, so a
 * determined attacker spread across instances gets more than the nominal quota.
 * It reliably stops the actual failure mode — a single client looping the
 * endpoint and draining the Shodan or Hunter quota — and it needs no extra
 * infrastructure. A shared store (Upstash, Vercel KV) is the correct fix if
 * this ever faces real traffic.
 */

interface Window {
  count: number;
  resetAt: number;
}

const windows = new Map<string, Window>();

/** Stop the map growing without bound on a long-lived instance. */
function evictExpired(now: number): void {
  for (const [key, window] of windows) {
    if (window.resetAt <= now) windows.delete(key);
  }
}

export function clientIp(request: NextRequest): string {
  // Vercel sets x-forwarded-for; the client's address is the first entry.
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return request.headers.get("x-real-ip") ?? "unknown";
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

export function rateLimit(
  key: string,
  limit: number,
  windowMs: number
): RateLimitResult {
  const now = Date.now();
  if (windows.size > 500) evictExpired(now);

  const existing = windows.get(key);
  if (!existing || existing.resetAt <= now) {
    windows.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSeconds: 0 };
  }

  existing.count += 1;
  if (existing.count > limit) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
    };
  }
  return { allowed: true, retryAfterSeconds: 0 };
}
