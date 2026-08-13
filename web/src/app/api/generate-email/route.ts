import { NextRequest, NextResponse } from "next/server";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { GEMINI_MODEL, restoreCompanyDomain } from "@/lib/gemini";
import { formatCurrency } from "@/lib/constants";
import { rateLimit, clientIp } from "@/lib/rate-limit";

/**
 * Placeholder booking link for the demo. Swap for the real scheduling URL
 * before this is ever sent to an actual prospect.
 */
const BOOKING_LINK = "https://cal.com/security-research-team/30min";

interface VulnDetail {
  cveId: string;
  cvss: number | null;
  epss: number | null;
  /** Plain-English headline, classified in code from the summary. */
  title?: string;
  summary: string | null;
  inKev: boolean | null;
  ransomware?: boolean;
}

interface EmailRequestBody {
  company: string;
  country: string | null;
  tier: string | null;
  inKev: boolean | null;
  ransomware: boolean | null;
  cveCount: number | null;
  maxCvss: number | null;
  maxEpss: number | null;
  estimatedExposure: number | null;
  ibmBreachCost: number;
  vulns: VulnDetail[];
}

const EMAIL_LIMIT = 10;
const EMAIL_WINDOW_MS = 60_000;

export async function POST(request: NextRequest) {
  const limit = rateLimit(`email:${clientIp(request)}`, EMAIL_LIMIT, EMAIL_WINDOW_MS);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: `Too many drafts. Try again in ${limit.retryAfterSeconds}s.` },
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

  const body: EmailRequestBody = await request.json();

  const attackPercent =
    body.maxEpss !== null ? `${Math.round(body.maxEpss * 100)}%` : null;

  // Computed here and interpolated as text; the model phrases it, never derives it.
  const exposureExact =
    body.estimatedExposure !== null ? formatCurrency(body.estimatedExposure) : null;

  // No dollar figure in the subject. It reads as spam, trips filters, and
  // asserts a cost this scan cannot know for one company. Their own domain plus
  // a specific, checkable observation is harder to ignore and easier to defend.
  const subjectLine = `Vulnerable software versions visible on ${body.company}`;

  // The "actively exploited / on the KEV list" claim is only true when the
  // company actually has a KEV hit. Asserting it otherwise would be a straight
  // fabrication in an email that gets sent, so the sentence branches on the data.
  const riskSentence = body.inKev
    ? `Our scan shows ${body.company} running software versions affected by vulnerabilities on the CISA Known Exploited Vulnerabilities list, which attackers are leveraging in the wild right now.`
    : `Our scan shows ${body.company} running software versions affected by known vulnerabilities, the most serious carrying a ${attackPercent ?? "measurable"} probability of being attacked in the next 30 days.`;

  const costSentence = exposureExact
    ? `These vulnerabilities represent an estimated ${exposureExact} in valuation and damages.`
    : `These vulnerabilities represent material exposure in valuation and damages.`;

  // Locked verbatim rather than described. Left to paraphrase, the model reaches
  // for "we invite you to..." — a pitch tone. This is deliberately take-it-or-
  // leave-it, and it carries no per-company data, so there is nothing to adapt.
  const ctaSentence = `If you are interested in fixing this, feel free to book a call: ${BOOKING_LINK}`;

  const prompt = `You are writing a very short outbound sales email for a cybersecurity software company, addressed to the team at ${body.company}${body.country ? ` in ${body.country}` : ""}.

Use ONLY the facts given below. Do not invent or alter any number, percentage or claim. Do not mention CVE IDs.

FORMAT — follow exactly, nothing else:

Subject: ${subjectLine}

Dear team@${body.company},

<sentence 1>
<sentence 2>
<sentence 3>

The Security Research Team

RULES:
- The body is exactly THREE sentences, each on its own line, with a blank line between them. No paragraphs, no bullet points, no extra commentary, no postscript.
- Sentence 1 must convey exactly this, and you may lightly reword it but must not add or drop any fact: "${riskSentence}"
- This is an external scan of advertised software versions, not a confirmed breach or a test of their systems. Never state that they "have" a vulnerability or that they have been compromised. Say what was observed, and invite them to check.
- Sentence 2 must state the cost and must contain the figure ${exposureExact ?? "as given"} written exactly like that, digits and all: "${costSentence}"
- Sentence 3 must be reproduced EXACTLY as written here, word for word, including the URL. Do not reword it, do not make it warmer, do not add "we invite you" or any similar phrasing: "${ctaSentence}"
- Use the subject line exactly as given above.
- The company's domain is exactly "${body.company}". Use that literal string. Never substitute a placeholder such as example.com, acme.com or yourcompany.com — this email is sent as written.
- No square brackets, no placeholders, no "[Your Name]". Output the finished email only.`;

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });
    const result = await model.generateContent(prompt);
    const emailText = restoreCompanyDomain(result.response.text(), body.company);

    return NextResponse.json({ email: emailText });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Failed to generate email";
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
