import { supabase } from "@/lib/supabase";
import { CompanyList } from "@/components/company-list";
import {
  sortCompaniesByTier,
  IBM_BREACH_COST_KEY,
  PAGE_SIZE,
} from "@/lib/constants";
import type { Company } from "@/lib/types";

interface SearchParams {
  tier?: string;
  country?: string;
  search?: string;
  page?: string;
}

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const tierFilter = params.tier ?? "all";
  const countryFilter = params.country ?? "all";
  const searchQuery = params.search ?? "";
  const currentPage = Math.max(1, parseInt(params.page ?? "1", 10));

  // count: "estimated" rather than "exact". An exact count scans the whole
  // table on every render; estimated uses the planner's figure once the table
  // is large and falls back to exact while it is small, so pagination is
  // accurate today and stays cheap as the table grows.
  let query = supabase.from("Companies").select("*", { count: "estimated" });

  if (tierFilter !== "all") {
    query = query.eq("tier", tierFilter);
  }
  if (countryFilter !== "all") {
    query = query.eq("country", countryFilter);
  }
  if (searchQuery) {
    query = query.ilike("company", `%${searchQuery}%`);
  }

  const offset = (currentPage - 1) * PAGE_SIZE;

  // Issued together, not in sequence. These three queries are independent, and
  // the functions run in syd1 alongside the database — but a serial chain still
  // pays three round trips where one will do.
  const [companiesResult, settingResult, countryResult] = await Promise.all([
    query.order("max_epss", { ascending: false }).range(offset, offset + PAGE_SIZE - 1),
    supabase.from("settings").select("value").eq("key", IBM_BREACH_COST_KEY).single(),
    // A view doing SELECT DISTINCT server-side. This previously pulled every
    // Companies row to derive the list in JS, which PostgREST silently capped
    // at 1000 rows — so the dropdown was both wasteful and incomplete.
    supabase.from("company_countries").select("country").order("country"),
  ]);

  const { data: companies, count } = companiesResult;
  const { data: setting } = settingResult;

  const distinctCountries = (countryResult.data ?? [])
    .map((row) => row.country)
    .filter(Boolean) as string[];

  const sortedCompanies = sortCompaniesByTier((companies ?? []) as Company[]);
  const ibmBreachCost = setting?.value ?? 4_400_000;
  const totalPages = Math.ceil((count ?? 0) / PAGE_SIZE);

  return (
    <CompanyList
      companies={sortedCompanies}
      currentPage={currentPage}
      totalPages={totalPages}
      ibmBreachCost={ibmBreachCost}
      countries={distinctCountries}
      currentTier={tierFilter}
      currentCountry={countryFilter}
      currentSearch={searchQuery}
    />
  );
}
