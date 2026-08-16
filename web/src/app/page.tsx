import { Suspense } from "react";
import { CompanyList } from "@/components/company-list";
import { sortCompaniesByTier } from "@/lib/constants";
import { getCompaniesPage, getCountries } from "@/lib/queries";

interface SearchParams {
  tier?: string;
  country?: string;
  search?: string;
  page?: string;
  after?: string;
}


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
  const cursor = params.after ?? null;

  
  const [{ companies, totalPages, nextCursor }, countries] = await Promise.all([
    getCompaniesPage(tierFilter, countryFilter, searchQuery, currentPage, cursor),
    getCountries(),
  ]);

  return (
    <CompanyList
      companies={sortCompaniesByTier(companies)}
      currentPage={currentPage}
      totalPages={totalPages}
      nextCursor={nextCursor}
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
