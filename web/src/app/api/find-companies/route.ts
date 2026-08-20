import { NextRequest, NextResponse } from "next/server";
import { supabaseServer } from "@/lib/supabase-server";
import {
  buildKevMap,
  queryShodanApi,
  runPipeline,
} from "@/lib/pipeline";
import kevData from "@/data/kev.json";
import { sortCompaniesByTier } from "@/lib/constants";
import { rateLimit, clientIp } from "@/lib/rate-limit";
import { supabaseVerdictStore } from "@/lib/verdict-store";
import { confirmedActiveForDomain } from "@/lib/live-threat";
import { revalidateTag } from "next/cache";
import { CACHE_TAGS } from "@/lib/queries";

interface FindCompaniesRequestBody {
  country?: string;
  product?: string;
}

const COUNTRY_PATTERN = /^[A-Za-z]{2}$/;
const PRODUCT_PATTERN = /^[A-Za-z0-9._-]{1,40}$/;

/** One live run costs a Shodan credit and a Gemini call, so keep it tight. */
const FIND_LIMIT = 5;
const FIND_WINDOW_MS = 60_000;

export async function POST(request: NextRequest) {
  const limit = rateLimit(`find:${clientIp(request)}`, FIND_LIMIT, FIND_WINDOW_MS);
  if (!limit.allowed) {
    return NextResponse.json(
      { error: `Too many pipeline runs. Try again in ${limit.retryAfterSeconds}s.` },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSeconds) } }
    );
  }

  const shodanApiKey = process.env.SHODAN_API_KEY;
  if (!shodanApiKey) {
    return NextResponse.json(
      { error: "Shodan API key is not configured. Set SHODAN_API_KEY in .env.local" },
      { status: 500 }
    );
  }

  const geminiApiKey = process.env.GEMINI_API_KEY;
  if (!geminiApiKey) {
    return NextResponse.json(
      { error: "Gemini API key is not configured. Set GEMINI_API_KEY in .env.local" },
      { status: 500 }
    );
  }

  const body: FindCompaniesRequestBody = await request.json();

  if (!body.country && !body.product) {
    return NextResponse.json(
      { error: "At least one of country or product must be provided" },
      { status: 400 }
    );
  }

  const country = body.country?.trim();
  const product = body.product?.trim();

  if (country && !COUNTRY_PATTERN.test(country)) {
    return NextResponse.json(
      { error: "Country must be a two-letter code, for example US, DE or NL." },
      { status: 400 }
    );
  }
  if (product && !PRODUCT_PATTERN.test(product)) {
    return NextResponse.json(
      { error: "Product must be a single keyword, for example nginx, Apache or OpenSSH." },
      { status: 400 }
    );
  }

  const target: { country?: string; product?: string } = {};
  if (country) target.country = country;
  if (product) target.product = product;

  try {
    // Stage 1: Query Shodan API
    const shodanRecords = await queryShodanApi(shodanApiKey, target);

    if (shodanRecords.length === 0) {
      return NextResponse.json({
        message: "No records found from Shodan for the given target.",
        companiesFound: 0,
        companiesUpserted: 0,
        vulnsUpserted: 0,
      });
    }

    // Build KEV map from bundled CISA data
    const kevMap = buildKevMap(
      kevData as { vulnerabilities: { cveID: string; knownRansomwareCampaignUse: string }[] }
    );

    // Stages 2–5: Run the cleaning pipeline
    const pipelineResult = await runPipeline(
      shodanRecords,
      kevMap,
      geminiApiKey,
      supabaseVerdictStore
    );

    if (pipelineResult.companies.length === 0) {
      return NextResponse.json({
        message: `Processed ${pipelineResult.totalRecordsProcessed} records but no resolvable companies found.`,
        companiesFound: 0,
        companiesUpserted: 0,
        vulnsUpserted: 0,
        recordsProcessed: pipelineResult.totalRecordsProcessed,
        domainsDropped: pipelineResult.domainsDropped,
      });
    }

    // Stage 5b: live-threat flag. Gated to in_kev companies — "confirmed active"
    // builds on "actively exploited" — and domain-only, so no IP is needed. N is
    // small per run (Shodan is capped at 100 records), so this stays well inside
    // the abuse.ch limits. A missing key or a feed hiccup leaves the flag false.
    const abusechKey = process.env.ABUSECH_AUTH_KEY;
    if (abusechKey) {
      const kevCompanies = pipelineResult.companies.filter((company) => company.in_kev);
      await Promise.all(
        kevCompanies.map(async (company) => {
          const flag = await confirmedActiveForDomain(company.company, abusechKey);
          company.confirmed_active = flag.confirmed_active;
          company.active_source = flag.active_source;
          company.active_detail = flag.active_detail;
          company.active_checked_at = flag.active_checked_at;
        })
      );
    }

    // Stage 6: Upsert into Supabase
    const { error: companyUpsertError } = await supabaseServer
      .from("Companies")
      .upsert(pipelineResult.companies, { onConflict: "company" });

    if (companyUpsertError) {
      return NextResponse.json(
        {
          error: `Failed to upsert companies: ${companyUpsertError.message}`,
          companiesFound: pipelineResult.companies.length,
        },
        { status: 500 }
      );
    }

    let vulnsUpserted = 0;
    if (pipelineResult.vulns.length > 0) {
      const { error: vulnUpsertError } = await supabaseServer
        .from("Company_Vulns")
        .upsert(pipelineResult.vulns, { onConflict: "company,cve_id" });

      if (vulnUpsertError) {
        // Companies were saved; vulns failed — report partial success
        return NextResponse.json({
          message: `Upserted ${pipelineResult.companies.length} companies but failed to save vulnerability details: ${vulnUpsertError.message}`,
          companiesFound: pipelineResult.companies.length,
          companiesUpserted: pipelineResult.companies.length,
          vulnsUpserted: 0,
          recordsProcessed: pipelineResult.totalRecordsProcessed,
          domainsDropped: pipelineResult.domainsDropped,
        });
      }
      vulnsUpserted = pipelineResult.vulns.length;
    }

    
    revalidateTag(CACHE_TAGS.companies, "max");

    return NextResponse.json({
      message: `Found and upserted ${pipelineResult.companies.length} companies from ${pipelineResult.totalRecordsProcessed} Shodan records.`,
      companiesFound: pipelineResult.companies.length,
      companiesUpserted: pipelineResult.companies.length,
      vulnsUpserted,
      recordsProcessed: pipelineResult.totalRecordsProcessed,
      domainsDropped: pipelineResult.domainsDropped,
    
      resolution: pipelineResult.resolution,
    
      companies: sortCompaniesByTier(pipelineResult.companies).map((company) => ({
        company: company.company,
        country: company.country,
        tier: company.tier,
        cveCount: company.cve_count,
      })),
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Failed to run pipeline";
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
