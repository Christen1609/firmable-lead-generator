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

  let query = supabase.from("Companies").select("*", { count: "exact" });

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
  const { data: companies, count } = await query
    .order("max_epss", { ascending: false })
    .range(offset, offset + PAGE_SIZE - 1);

  const { data: setting } = await supabase
    .from("settings")
    .select("value")
    .eq("key", IBM_BREACH_COST_KEY)
    .single();

  const { data: countryRows } = await supabase
    .from("Companies")
    .select("country")
    .not("country", "is", null)
    .order("country");

  const distinctCountries = [
    ...new Set(
      (countryRows ?? []).map((row) => row.country).filter(Boolean)
    ),
  ].sort() as string[];

  const sortedCompanies = sortCompaniesByTier((companies ?? []) as Company[]);
  const ibmBreachCost = setting?.value ?? 4_400_000;
  const totalPages = Math.ceil((count ?? 0) / PAGE_SIZE);

  return (
    <CompanyList
      companies={sortedCompanies}
      totalCount={count ?? 0}
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
