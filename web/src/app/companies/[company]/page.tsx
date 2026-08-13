import { Suspense } from "react";
import { notFound } from "next/navigation";
import { getCompanyVulns } from "@/lib/vuln-data";
import { CompanyDetail } from "@/components/company-detail";
import { computeEstimatedExposure } from "@/lib/constants";
import { getCompany, getIbmBreachCost } from "@/lib/queries";

interface PageProps {
  params: Promise<{ company: string }>;
}

/**
 * Reading params is dynamic, so it sits behind the Suspense boundary below.
 * The company row and the IBM figure are both cached; only the per-company
 * findings query still reaches Postgres on every view.
 */
async function CompanyDetailContent({ params }: PageProps) {
  const { company: companyParam } = await params;
  const companyName = decodeURIComponent(companyParam);

  const [company, vulns, ibmBreachCost] = await Promise.all([
    getCompany(companyName),
    getCompanyVulns(companyName),
    getIbmBreachCost(),
  ]);

  if (!company) {
    notFound();
  }

  const estimatedExposure = computeEstimatedExposure(
    company.max_epss,
    ibmBreachCost
  );

  return (
    <CompanyDetail
      company={company}
      vulns={vulns}
      ibmBreachCost={ibmBreachCost}
      estimatedExposure={estimatedExposure}
    />
  );
}

export default function CompanyDetailPage({ params }: PageProps) {
  return (
    <Suspense fallback={<div style={{ minHeight: "100vh", background: "var(--color-bg)" }} />}>
      <CompanyDetailContent params={params} />
    </Suspense>
  );
}
