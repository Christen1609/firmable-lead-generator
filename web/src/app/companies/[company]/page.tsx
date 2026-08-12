import { notFound } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { getCompanyVulns } from "@/lib/vuln-data";
import { CompanyDetail } from "@/components/company-detail";
import {
  IBM_BREACH_COST_KEY,
  computeEstimatedExposure,
} from "@/lib/constants";
import type { Company } from "@/lib/types";

interface PageProps {
  params: Promise<{ company: string }>;
}

export default async function CompanyDetailPage({ params }: PageProps) {
  const { company: companyParam } = await params;
  const companyName = decodeURIComponent(companyParam);

  const { data: company } = await supabase
    .from("Companies")
    .select("*")
    .eq("company", companyName)
    .single();

  if (!company) {
    notFound();
  }

  const vulns = await getCompanyVulns(companyName);

  const { data: setting } = await supabase
    .from("settings")
    .select("value")
    .eq("key", IBM_BREACH_COST_KEY)
    .single();

  const ibmBreachCost = setting?.value ?? 4_400_000;
  const estimatedExposure = computeEstimatedExposure(
    (company as Company).max_epss,
    ibmBreachCost
  );

  return (
    <CompanyDetail
      company={company as Company}
      vulns={vulns}
      ibmBreachCost={ibmBreachCost}
      estimatedExposure={estimatedExposure}
    />
  );
}
