import "server-only";
import { supabaseServer } from "@/lib/supabase-server";
import type { VerdictStore } from "@/lib/pipeline";

type Verdict = "business" | "infrastructure";


export const supabaseVerdictStore: VerdictStore = {
  async get(domains) {
    const verdicts = new Map<string, Verdict>();
    if (domains.length === 0) return verdicts;

    const { data, error } = await supabaseServer
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

    const { error } = await supabaseServer
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
