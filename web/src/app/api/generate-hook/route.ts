import { NextRequest, NextResponse } from "next/server";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { GEMINI_MODEL, restoreCompanyDomain } from "@/lib/gemini";
import { formatCurrency } from "@/lib/constants";
import { rateLimit, clientIp } from "@/lib/rate-limit";

/**
 * The spoken opener for a cold call — what a salesperson says in the first ten
 * seconds, not something they send.
 *
 * Same guardrail as the outreach email: every figure is computed here and
 * passed to the model as text. The model chooses phrasing, never arithmetic.
 */

interface HookRequestBody {
  company: string;
  tier: string | null;
  inKev: boolean | null;
  ransomware: boolean | null;
  maxEpss: number | null;
  cveCount: number | null;
  estimatedExposure: number | null;
  ibmBreachCost: number;
  topFinding: string | null;
}

const HOOK_LIMIT = 10;
const HOOK_WINDOW_MS = 60_000;

export async function POST(request: NextRequest) {
  const limit = rateLimit(`hook:${clientIp(request)}`, HOOK_LIMIT, HOOK_WINDOW_MS);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: `Too many hooks. Try again in ${limit.retryAfterSeconds}s.` },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSeconds) } }
    );
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "Gemini API key is not configured. Set GEMINI_API_KEY in .env.local" },
      { status: 500 }
    );
  }

  const body: HookRequestBody = await request.json();

  const attackPercent =
    body.maxEpss !== null ? `${Math.round(body.maxEpss * 100)}%` : null;
  const exposure =
    body.estimatedExposure !== null ? formatCurrency(body.estimatedExposure) : null;

  // Only claim active exploitation when the company actually has a KEV hit —
  // this gets said out loud to a real person, so it has to be true.
  const threatLine = body.inKev
    ? `a flaw on their systems that is confirmed to be under active attack in the wild right now`
    : `a flaw on their systems with a ${attackPercent ?? "measurable"} chance of being attacked in the next 30 days`;

  // The cost figure is IBM's average breach cost scaled by this company's own
  // attack probability. It is an estimate, not a record of a past incident, and
  // the wording must not imply otherwise.
  const costLine = exposure
    ? `Breaches like this cost ${formatCurrency(body.ibmBreachCost)} on average, which puts this company's own exposure at roughly ${exposure}.`
    : `Breaches like this cost ${formatCurrency(body.ibmBreachCost)} on average.`;

  const prompt = `Write a short spoken opener a salesperson says on a cold call to someone at ${body.company}. This is speech, not an email — no subject line, no greeting, no sign-off.

Use ONLY these facts. Do not invent or change any number:
- The company is ${body.company}
- They have ${threatLine}
${body.topFinding ? `- The worst issue in plain English: ${body.topFinding}` : ""}
${body.cveCount ? `- Number of distinct vulnerabilities visible from outside: ${body.cveCount}` : ""}
- ${costLine}
${body.ransomware ? "- At least one of these flaws is used by known ransomware groups" : ""}

RULES:
- Exactly 3 sentences, no more.
- Sentence 1: name what is wrong, in plain English a non-technical owner follows.
- Sentence 2: the money. State the cost as an average and this company's exposure as an estimate. Never say or imply this company was already breached, and never claim a past incident.
- Sentence 3: a short question asking if they would want it fixed.
- Conversational and direct, the way a person actually talks. No jargon, no CVE IDs, no percentages read out as decimals.
- Refer to the company the way you would say it out loud — dropping the domain suffix is fine and usually sounds better ("Transip" rather than "transip dot net"). Never substitute a different company, and never use a placeholder like example.com.
- Do not use the words "cyber", "solution", "leverage", "reach out" or "circle back".
- Output only the spoken words. No labels, no quotes around it, no stage directions.`;

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });
    const result = await model.generateContent(prompt);
    const hook = restoreCompanyDomain(result.response.text().trim(), body.company);

    return NextResponse.json({ hook });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to generate hook";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
