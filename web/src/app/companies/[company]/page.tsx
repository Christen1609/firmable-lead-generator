import { Suspense } from "react";
import { notFound } from "next/navigation";
import { getCompanyVulns } from "@/lib/vuln-data";
import { rewriteMissingSummaries } from "@/lib/rewrite";
import { CompanyDetail } from "@/components/company-detail";
import { computeEstimatedExposure } from "@/lib/constants";
import { getCompany, getIbmBreachCost } from "@/lib/queries";

interface PageProps {
  params: Promise<{ company: string }>;
}


async function CompanyDetailContent({ params }: PageProps) {
  const { company: companyParam } = await params;
  const companyName = decodeURIComponent(companyParam);

  const [company, rawVulns, ibmBreachCost] = await Promise.all([
    getCompany(companyName),
    getCompanyVulns(companyName),
    getIbmBreachCost(),
  ]);

  if (!company) {
    notFound();
  }

  // Fill in a plain-English rewrite for any on-screen flaw that lacks one (a
  // brand-new CVE a live run just introduced), so it appears in this view.
  const vulns = await rewriteMissingSummaries(rawVulns);

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
