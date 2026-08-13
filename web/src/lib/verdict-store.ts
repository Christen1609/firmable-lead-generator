import "server-only";
import { supabaseAdmin } from "@/lib/supabase-admin";
import type { VerdictStore } from "@/lib/pipeline";

type Verdict = "business" | "infrastructure";

/**
 * Persisted classifier verdicts, keyed by domain.
 *
 * A domain's classification does not change between runs, and the same domains
 * recur constantly across targets, so re-asking is pure waste — an API call and
 * a slice of the context window spent to relearn something already known.
 *
 * Failures here are swallowed by the caller on purpose: this is a cost
 * optimisation, and losing the cache must degrade the pipeline to "ask the
 * model again", never break the run.
 */
export const supabaseVerdictStore: VerdictStore = {
  async get(domains) {
    const verdicts = new Map<string, Verdict>();
    if (domains.length === 0) return verdicts;

    const { data, error } = await supabaseAdmin
      .from("Domain_Classifications")
      .select("domain,verdict")
      .in("domain", domains);

    if (error) throw new Error(error.message);

    for (const row of data ?? []) {
      verdicts.set(row.domain as string, row.verdict as Verdict);
    }
    return verdicts;
  },

  async put(entries) {
    if (entries.length === 0) return;

    const { error } = await supabaseAdmin
      .from("Domain_Classifications")
      .upsert(
        entries.map((entry) => ({
          domain: entry.domain,
          verdict: entry.verdict,
          classified_at: new Date().toISOString(),
        })),
        { onConflict: "domain" }
      );

    if (error) throw new Error(error.message);
  },
};
