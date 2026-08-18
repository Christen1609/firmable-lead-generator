import { cacheTag, cacheLife } from "next/cache";
import { supabasePublic } from "@/lib/supabase-public";
import { IBM_BREACH_COST_KEY, PAGE_SIZE } from "@/lib/constants";
import type { Company } from "@/lib/types";



const COMPANIES_TAG = "companies";

const SETTINGS_TAG = "settings";

export interface CompaniesPage {
  companies: Company[];
  totalPages: number;
  nextCursor: string | null;
}

const CURSOR_COMPANY = /^[A-Za-z0-9.-]{1,253}$/;

export function encodeCursor(company: Company): string {
  return [
    company.max_epss ?? 0,
    company.ransomware ? 1 : 0,
    company.cve_count ?? 0,
    company.company,
  ].join("~");
}

function decodeCursor(raw: string) {
  const parts = raw.split("~");
  if (parts.length !== 4) return null;
  const epss = Number(parts[0]);
  const ransomware = parts[1] === "1";
  const cveCount = Number(parts[2]);
  const company = parts[3];
  if (!Number.isFinite(epss) || !Number.isFinite(cveCount)) return null;
  if (!CURSOR_COMPANY.test(company)) return null;
  return { epss, ransomware, cveCount, company };
}

export async function getCompaniesPage(
  tier: string,
  country: string,
  search: string,
  page: number,
  cursor: string | null = null
): Promise<CompaniesPage> {
  "use cache";
  cacheTag(COMPANIES_TAG);
  cacheLife("minutes");

  let query = supabasePublic.from("Companies").select("*", { count: "estimated" });

  if (tier !== "all") query = query.eq("tier", tier);
  if (country !== "all") query = query.eq("country", country);
  if (search) query = query.ilike("company", `%${search}%`);

  const seek = cursor ? decodeCursor(cursor) : null;

  if (seek) {
    const r = seek.ransomware;
    query = query.or(
      [
        `max_epss.lt.${seek.epss}`,
        `and(max_epss.eq.${seek.epss},ransomware.lt.${r})`,
        `and(max_epss.eq.${seek.epss},ransomware.eq.${r},cve_count.lt.${seek.cveCount})`,
        `and(max_epss.eq.${seek.epss},ransomware.eq.${r},cve_count.eq.${seek.cveCount},company.lt.${seek.company})`,
      ].join(",")
    );
  }

  query = query
    .order("max_epss", { ascending: false })
    .order("ransomware", { ascending: false })
    .order("cve_count", { ascending: false })
    .order("company", { ascending: false });

  const { data, count } = seek
    ? await query.limit(PAGE_SIZE)
    : await query.range((page - 1) * PAGE_SIZE, (page - 1) * PAGE_SIZE + PAGE_SIZE - 1);

  const companies = (data ?? []) as Company[];

  return {
    companies,
    totalPages: Math.ceil((count ?? 0) / PAGE_SIZE),
    nextCursor:
      companies.length === PAGE_SIZE
        ? encodeCursor(companies[companies.length - 1])
        : null,
  };
}


export async function getCountries(): Promise<string[]> {
  "use cache";
  cacheTag(COMPANIES_TAG);
  cacheLife("days");

  const { data } = await supabasePublic
    .from("company_countries")
    .select("country")
    .order("country");

  return (data ?? []).map((row) => row.country).filter(Boolean) as string[];
}


export async function getIbmBreachCost(): Promise<number> {
  "use cache";
  cacheTag(SETTINGS_TAG);
  cacheLife("days");

  const { data } = await supabasePublic
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

  const { data } = await supabasePublic
    .from("Companies")
    .select("*")
    .eq("company", companyName)
    .single();

  return (data as Company) ?? null;
}

/** Tags the pipeline purges after a write. */
export const CACHE_TAGS = { companies: COMPANIES_TAG, settings: SETTINGS_TAG };
