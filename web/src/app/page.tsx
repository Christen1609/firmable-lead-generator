import { Suspense } from "react";
import { CompanyList } from "@/components/company-list";
import { sortCompaniesByTier } from "@/lib/constants";
import { getCompaniesPage, getCountries, getIbmBreachCost } from "@/lib/queries";

interface SearchParams {
  tier?: string;
  country?: string;
  search?: string;
  page?: string;
}

/**
 * Reading searchParams is inherently dynamic, so it lives in this inner
 * component behind a Suspense boundary. That lets Next prerender a static shell
 * for the route and stream this in, while the queries it calls are themselves
 * cached per filter combination.
 */
async function ProspectList({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const tierFilter = params.tier ?? "all";
  const countryFilter = params.country ?? "all";
  const searchQuery = params.search ?? "";
  const currentPage = Math.max(1, parseInt(params.page ?? "1", 10));

  // Plain values only — a `use cache` scope cannot read searchParams itself, so
  // the filters are passed in as arguments and become part of the cache key.
  const [{ companies, totalPages }, countries, ibmBreachCost] = await Promise.all([
    getCompaniesPage(tierFilter, countryFilter, searchQuery, currentPage),
    getCountries(),
    getIbmBreachCost(),
  ]);

  return (
    <CompanyList
      companies={sortCompaniesByTier(companies)}
      currentPage={currentPage}
      totalPages={totalPages}
      ibmBreachCost={ibmBreachCost}
      countries={countries}
      currentTier={tierFilter}
      currentCountry={countryFilter}
      currentSearch={searchQuery}
    />
  );
}

export default function Home({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  return (
    <Suspense fallback={<div style={{ minHeight: "100vh", background: "var(--color-bg)" }} />}>
      <ProspectList searchParams={searchParams} />
    </Suspense>
  );
}
