import "server-only";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { GEMINI_MODEL } from "@/lib/gemini";
import { supabasePublic } from "@/lib/supabase-public";
import { supabaseServer } from "@/lib/supabase-server";
import type { CompanyVuln } from "@/lib/types";

/**
 * Lazy, on-read rewrite of any on-screen CVE that has no plain-English summary
 * yet. Backfills the common case once (rewrite_summaries.py); this covers the
 * rare brand-new CVE a live "Find More" run just introduced, so its plain text
 * is present in THE SAME page view rather than on some later visit.
 *
 * Guarded exactly like the batch script: the rewrite may not add a product,
 * version or number absent from the source, may not claim a breach, may not
 * echo a CVE id, and is discarded (card falls back to the raw summary) if it
 * breaks a rule. Every accepted rewrite is written to Cve_Plain_Summaries and
 * reused forever, so this runs at most once per CVE.
 */

const MAX_REWRITE_CHARS = 320;
const FORBIDDEN = [
  "breach", "hacked", "compromis", "you were", "your company",
  "your organisation", "your organization", "already been",
];
const NUMBER = /\d+(?:\.\d+)*/g;
const CVE_ID = /cve-\d{4}-\d+/i;

const PROMPT_HEAD =
  "You are rewriting software vulnerability descriptions for a non-technical " +
  "business owner.\n\n" +
  "For each item, rewrite the description into ONE or TWO short, plain sentences " +
  "saying, in everyday words, what the flaw is and what it could let an attacker do.\n\n" +
  "Rules:\n" +
  "- Use ONLY facts in the given text. Do NOT add any product name, version " +
  "number, or figure that is not already in the text.\n" +
  "- Do NOT say the company has been breached, hacked, or compromised.\n" +
  "- Do NOT mention the CVE identifier.\n" +
  "- No jargon or acronyms; keep each rewrite under 40 words.\n\n" +
  'Return ONLY a JSON array, one object per item, using the item\'s number as ' +
  '"id": [{"id": 1, "text": "<rewrite>"}]\n\nItems:\n';

/** Reconcile one rewrite against its source; returns the text or null. */
function accept(rewrite: string, source: string): string | null {
  const text = (rewrite || "").trim();
  if (!text || text.length > MAX_REWRITE_CHARS) return null;
  const low = text.toLowerCase();
  if (FORBIDDEN.some((word) => low.includes(word))) return null;
  if (CVE_ID.test(text)) return null;
  for (const token of text.match(NUMBER) ?? []) {
    if (!source.includes(token)) return null; // no invented numbers/versions
  }
  return text;
}

function parseJsonArray(text: string): { id?: number; text?: string }[] {
  const cleaned = text.trim().replace(/^```(?:json)?/m, "").replace(/```$/m, "").trim();
  const start = cleaned.indexOf("[");
  const end = cleaned.lastIndexOf("]");
  if (start === -1 || end === -1) return [];
  try {
    return JSON.parse(cleaned.slice(start, end + 1));
  } catch {
    return [];
  }
}

/**
 * Returns `vulns` with plain_summary filled for any that were missing it —
 * first from a fresh table read (in case the cached list was stale), then from
 * a single guarded Gemini call for whatever is still absent. Never throws.
 */
export async function rewriteMissingSummaries(
  vulns: CompanyVuln[]
): Promise<CompanyVuln[]> {
  const apiKey = process.env.GEMINI_API_KEY;
  const missing = vulns.filter((v) => !v.plain_summary && v.summary);
  if (missing.length === 0) return vulns;

  const resolved = new Map<string, string>();

  // The cached findings list may lag the table — re-check before spending a call.
  try {
    const { data } = await supabasePublic
      .from("Cve_Plain_Summaries")
      .select("cve_id,plain_summary")
      .in("cve_id", missing.map((v) => v.cve_id));
    for (const row of data ?? []) {
      resolved.set(row.cve_id as string, row.plain_summary as string);
    }
  } catch { /* fall through to the model */ }

  const stillMissing = missing.filter((v) => !resolved.has(v.cve_id));
  if (apiKey && stillMissing.length > 0) {
    try {
      const listing = stillMissing
        .map((v, i) => `${i + 1}. ${(v.summary ?? "").slice(0, 600)}`)
        .join("\n");
      const model = new GoogleGenerativeAI(apiKey).getGenerativeModel({ model: GEMINI_MODEL });
      const result = await model.generateContent(PROMPT_HEAD + listing);

      const fresh: { cve_id: string; plain_summary: string }[] = [];
      for (const item of parseJsonArray(result.response.text())) {
        const index = Number(item.id) - 1;
        const target = stillMissing[index];
        if (!target) continue;
        const text = accept(item.text ?? "", target.summary ?? "");
        if (text) {
          resolved.set(target.cve_id, text);
          fresh.push({ cve_id: target.cve_id, plain_summary: text });
        }
      }
      if (fresh.length > 0) {
        await supabaseServer
          .from("Cve_Plain_Summaries")
          .upsert(fresh, { onConflict: "cve_id" });
      }
    } catch { /* leave those on the raw summary */ }
  }

  return vulns.map((v) =>
    v.plain_summary ? v : { ...v, plain_summary: resolved.get(v.cve_id) ?? null }
  );
}
