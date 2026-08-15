import { NextRequest, NextResponse } from "next/server";
import { rankContacts, type ContactCandidate } from "@/lib/contacts";
import { rateLimit, clientIp } from "@/lib/rate-limit";

/**
 * Contact lookup for one company, on demand.
 *
 * Called only when the user presses "Contact Info" on a company. Provider lookups are metered and most companies are
 * never opened, so doing this eagerly would burn the quota on nobody's behalf.
 *
 */

const HUNTER_DOMAIN_SEARCH = "https://api.hunter.io/v2/domain-search";
const MAX_CONTACTS = 3;


const HUNTER_PAGE_SIZE = 10;

interface HunterEmail {
  value: string;
  first_name: string | null;
  last_name: string | null;
  position: string | null;
  confidence: number | null;
  linkedin: string | null;
  department: string | null;
  seniority: string | null;
  decision_maker?: boolean | null;
  verification?: { status?: string | null } | null;
}

function fullName(email: HunterEmail): string | null {
  const parts = [email.first_name, email.last_name].filter(Boolean);
  return parts.length ? parts.join(" ") : null;
}

function toCandidates(emails: HunterEmail[]): ContactCandidate[] {
  return emails
    .filter((email) => Boolean(email.value))
    .map((email) => ({
      name: fullName(email),
      position: email.position,
      email: email.value,
      confidence: email.confidence,
      linkedin: email.linkedin,
      seniority: email.seniority,
      decisionMaker: Boolean(email.decision_maker),
      unreliable:
        email.verification?.status === "invalid" ||
        (email.confidence !== null && email.confidence < 50),
    }));
}

const CONTACTS_LIMIT = 10;
const CONTACTS_WINDOW_MS = 60_000;

export async function POST(request: NextRequest) {
  const limit = rateLimit(`contacts:${clientIp(request)}`, CONTACTS_LIMIT, CONTACTS_WINDOW_MS);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: `Too many lookups. Try again in ${limit.retryAfterSeconds}s.` },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSeconds) } }
    );
  }

  const apiKey = process.env.HUNTER_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "Hunter API key is not configured. Set HUNTER_API_KEY in .env.local" },
      { status: 500 }
    );
  }

  const body: { company?: string } = await request.json();
  const domain = body.company?.trim();
  if (!domain) {
    return NextResponse.json({ error: "company is required" }, { status: 400 });
  }

  const params = new URLSearchParams({
    domain,
    api_key: apiKey,
    limit: String(HUNTER_PAGE_SIZE),
  });

  try {
    const response = await fetch(`${HUNTER_DOMAIN_SEARCH}?${params.toString()}`);
    const payload = await response.json();

    if (!response.ok) {
      const detail =
        payload?.errors?.[0]?.details ??
        payload?.errors?.[0]?.id ??
        `Hunter returned ${response.status}`;
      return NextResponse.json({ error: detail }, { status: response.status });
    }

    const emails: HunterEmail[] = payload?.data?.emails ?? [];
    const contacts = rankContacts(toCandidates(emails), MAX_CONTACTS);

    return NextResponse.json({
      company: domain,
      organization: payload?.data?.organization ?? null,
      contacts,
    
      totalFound: emails.length,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to look up contacts";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
