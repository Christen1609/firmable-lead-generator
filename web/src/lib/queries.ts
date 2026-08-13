import { cacheTag, cacheLife } from "next/cache";
import { supabase } from "@/lib/supabase";
import { IBM_BREACH_COST_KEY, PAGE_SIZE } from "@/lib/constants";
import type { Company } from "@/lib/types";

/**
 * Cached read layer.
 *
 * Paging back and forth previously re-queried Postgres for every page view,
 * even though page 2 returns the same rows it returned thirty seconds ago. The
 * dataset only changes when the pipeline runs, so almost every one of those
 * round trips was avoidable.
 *
 * Each function is a `use cache` scope. Its cache key is derived from its
 * arguments, so every distinct filter/page combination gets its own entry and
 * revisiting a page is served from cache rather than the database.
 *
 * Invalidation is explicit, not time-based guesswork: the pipeline route calls
 * revalidateTag() after it writes, so new companies appear immediately rather
 * than after a TTL expires. The cacheLife values are the backstop for data
 * changed outside the app, such as a manual SQL edit.
 */

/** Everything derived from the Companies table. */
const COMPANIES_TAG = "companies";
/** The settings row. Separate tag: it changes on a completely different cadence. */
const SETTINGS_TAG = "settings";

export interface CompaniesPage {
  companies: Company[];
  totalPages: number;
}

export async function getCompaniesPage(
  tier: string,
  country: string,
  search: string,
  page: number
): Promise<CompaniesPage> {
  "use cache";
  cacheTag(COMPANIES_TAG);
  cacheLife("minutes");

  let query = supabase.from("Companies").select("*", { count: "estimated" });

  if (tier !== "all") query = query.eq("tier", tier);
  if (country !== "all") query = query.eq("country", country);
  if (search) query = query.ilike("company", `%${search}%`);

  const offset = (page - 1) * PAGE_SIZE;
  const { data, count } = await query
    .order("max_epss", { ascending: false })
    .range(offset, offset + PAGE_SIZE - 1);

  return {
    companies: (data ?? []) as Company[],
    totalPages: Math.ceil((count ?? 0) / PAGE_SIZE),
  };
}

/**
 * The country list changes only when the pipeline finds a company in a country
 * not already represented — a handful of times ever. Cached for a day.
 */
export async function getCountries(): Promise<string[]> {
  "use cache";
  cacheTag(COMPANIES_TAG);
  cacheLife("days");

  const { data } = await supabase
    .from("company_countries")
    .select("country")
    .order("country");

  return (data ?? []).map((row) => row.country).filter(Boolean) as string[];
}

/**
 * IBM's average breach cost. One row, changed by hand roughly never, and read
 * on every page of the app.
 */
export async function getIbmBreachCost(): Promise<number> {
  "use cache";
  cacheTag(SETTINGS_TAG);
  cacheLife("days");

  const { data } = await supabase
    .from("settings")
    .select("value")
    .eq("key", IBM_BREACH_COST_KEY)
    .single();

  return data?.value ?? 4_400_000;
}

export async function getCompany(companyName: string): Promise<Company | null> {
  "use cache";
  cacheTag(COMPANIES_TAG);
  cacheLife("minutes");

  const { data } = await supabase
    .from("Companies")
    .select("*")
    .eq("company", companyName)
    .single();

  return (data as Company) ?? null;
}

/** Tags the pipeline purges after a write. */
export const CACHE_TAGS = { companies: COMPANIES_TAG, settings: SETTINGS_TAG };
