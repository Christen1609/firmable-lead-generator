"use client";

import { useRouter } from "next/navigation";
import { useTransition, useState, useEffect } from "react";
import {
  TIER_BADGE_STYLES,
  TIER_FILTER_OPTIONS,
  computeEstimatedExposure,
  formatCurrencyShort,
  type TierBadgeStyle,
} from "@/lib/constants";
import type { Company } from "@/lib/types";
import { DotField } from "@/components/dot-field";
import { SpecularButton, specularPrimary } from "@/components/specular-button";
import { Radar, X, Loader2, ChevronDown } from "lucide-react";

interface CompanyListProps {
  companies: Company[];
  currentPage: number;
  totalPages: number;
  ibmBreachCost: number;
  countries: string[];
  currentTier: string;
  currentCountry: string;
  currentSearch: string;
}

/** One company as returned by a live pipeline run, for the results list. */
interface FoundCompany {
  company: string;
  country: string | null;
  tier: string;
  cveCount: number;
}

function badgeStyle(tier: string | null): TierBadgeStyle {
  return TIER_BADGE_STYLES[tier ?? "Low"] ?? TIER_BADGE_STYLES.Low;
}

function buildSignals(company: Company): string {
  const signals: string[] = [];
  if (company.in_kev) signals.push("Exploited in the wild");
  if (company.ransomware) signals.push("Ransomware-linked");
  return signals.length ? signals.join(" · ") : "None flagged";
}

/** Page numbers to show, with "…" standing in for the skipped stretches. */
function buildPageRange(current: number, total: number): (number | "…")[] {
  if (total <= 7) {
    return Array.from({ length: total }, (_, index) => index + 1);
  }

  const pages: (number | "…")[] = [1];
  if (current > 3) pages.push("…");
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);
  for (let page = start; page <= end; page++) pages.push(page);
  if (current < total - 2) pages.push("…");
  pages.push(total);
  return pages;
}

export function CompanyList({
  companies,
  currentPage,
  totalPages,
  ibmBreachCost,
  countries,
  currentTier,
  currentCountry,
  currentSearch,
}: CompanyListProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [searchInput, setSearchInput] = useState(currentSearch);
  const [showFindModal, setShowFindModal] = useState(false);
  const [countryDropdownOpen, setCountryDropdownOpen] = useState(false);
  const [findCountry, setFindCountry] = useState("");
  const [findProduct, setFindProduct] = useState("");
  const [isFinding, setIsFinding] = useState(false);
  const [findResult, setFindResult] = useState<string | null>(null);
  const [findError, setFindError] = useState<string | null>(null);
  const [foundCompanies, setFoundCompanies] = useState<FoundCompany[]>([]);

  // Resyncs the input when the URL changes from outside the box (back button,
  // Clear filters). The input is otherwise left alone while the user types.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSearchInput(currentSearch);
  }, [currentSearch]);

  useEffect(() => {
    if (searchInput === currentSearch) return;
    const debounceTimer = setTimeout(() => {
      pushRoute({ search: searchInput });
    }, 400);
    return () => clearTimeout(debounceTimer);
    // pushRoute is recreated every render; including it would restart the 400ms
    // debounce on each keystroke and defeat the debounce entirely.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput, currentSearch]);

  function pushRoute(overrides: Record<string, string | undefined>) {
    const params = new URLSearchParams();
    const tier = overrides.tier ?? currentTier;
    const country = overrides.country ?? currentCountry;
    const search = overrides.search ?? currentSearch;
    const page = overrides.page;
    if (tier !== "all") params.set("tier", tier);
    if (country !== "all") params.set("country", country);
    if (search) params.set("search", search);
    if (page && page !== "1") params.set("page", page);
    const queryString = params.toString();
    startTransition(() => {
      router.push(queryString ? `/?${queryString}` : "/");
    });
  }

  function handleTierChange(tierValue: string) {
    pushRoute({ tier: tierValue, page: "1" });
  }

  function handleCountryChange(countryValue: string) {
    pushRoute({ country: countryValue, page: "1" });
  }

  function handleClearFilters() {
    setSearchInput("");
    pushRoute({ tier: "all", country: "all", search: "", page: "1" });
  }

  function handlePageChange(newPage: number) {
    pushRoute({ page: String(newPage) });
  }

  const pageRange = buildPageRange(currentPage, totalPages);
  /** "all" is just the first option, so the dropdown renders from one template. */
  const countryOptions = ["all", ...countries];

  async function handleFindCompanies() {
    if (!findCountry && !findProduct) return;
    setIsFinding(true);
    setFindError(null);
    setFindResult(null);

    try {
      const response = await fetch("/api/find-companies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          country: findCountry || undefined,
          product: findProduct || undefined,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error ?? "Failed to find companies");
      }

      setFindResult(data.message ?? `Found ${data.companiesFound} companies.`);
      setFoundCompanies(data.companies ?? []);
      router.refresh();
    } catch (error) {
      setFindError(
        error instanceof Error ? error.message : "Something went wrong"
      );
    } finally {
      setIsFinding(false);
    }
  }

  function handleCloseFindModal() {
    if (isFinding) return;
    setShowFindModal(false);
    setFindCountry("");
    setFindProduct("");
    setFindResult(null);
    setFindError(null);
    setFoundCompanies([]);
  }

  return (
    <div style={{ minHeight: "100vh", background: "var(--color-bg)", position: "relative", isolation: "isolate" }}>
      {/* DotField background */}
      <div aria-hidden style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(1100px 520px at 10% -10%, rgba(198, 113, 57, 0.04), transparent 70%), radial-gradient(900px 460px at 90% 2%, rgba(122, 138, 94, 0.03), transparent 72%), radial-gradient(1300px 620px at 50% 112%, rgba(255, 255, 255, 0.6), transparent 70%)",
        }} />
        <DotField />
      </div>

      {/* Nav bar */}
      <div style={{
        position: "sticky", top: 0, zIndex: 20,
        borderBottom: "1px solid color-mix(in srgb, var(--color-text) 7%, transparent)",
        background: "color-mix(in srgb, var(--color-bg) 74%, transparent)",
        backdropFilter: "blur(14px)", WebkitBackdropFilter: "blur(14px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 24, padding: "18px clamp(24px, 3.5vw, 64px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginRight: "auto" }}>
            <span style={{ fontFamily: "var(--font-heading)", fontSize: 21 }}>Lead Generator</span>
            <span style={{
              fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 500,
              color: "color-mix(in srgb, var(--color-text) 45%, transparent)", paddingLeft: 4,
            }}>
              Exposure intelligence
            </span>
          </div>
        </div>
      </div>

      {/* List content */}
      <div style={{ position: "relative", zIndex: 1, padding: "0 clamp(24px, 3.5vw, 64px)" }}>
        <div style={{ paddingTop: 68 }}>
          <span className="bw-tag" style={{
            background: "color-mix(in srgb, var(--color-accent-100) 75%, transparent)",
            color: "var(--color-accent-800)",
            borderRadius: 999, padding: "6px 15px", fontSize: 11,
            letterSpacing: ".12em", textTransform: "uppercase", fontWeight: 600,
          }}>
            Prospects
          </span>
          <h1 style={{
            margin: "20px 0 0", fontFamily: "var(--font-heading)", fontWeight: 400,
            fontSize: 54, lineHeight: 1.04, letterSpacing: "-.015em", maxWidth: "16ch",
          }}>
            Who needs a call today
          </h1>
          <p style={{
            margin: "20px 0 0", fontSize: 17, lineHeight: 1.62, maxWidth: "60ch",
            textWrap: "pretty",
            color: "color-mix(in srgb, var(--color-text) 66%, transparent)",
          }}>
            Prospects built from public internet scan data and ranked by live
            exploitation signals. Critical means confirmed active exploitation.
          </p>
        </div>

        {/* Search + tier filters */}
        <div style={{
          marginTop: 38, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12,
        }}>
          <input
            className="bw-input"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search company"
            style={{ width: 260, height: 42, fontSize: 14 }}
          />
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginLeft: "auto" }}>
            {TIER_FILTER_OPTIONS.map((option) => (
              <button
                key={option.value}
                className={`bw-btn ${currentTier === option.value ? "bw-btn-primary" : "bw-btn-secondary"}`}
                onClick={() => handleTierChange(option.value)}
                style={{ borderRadius: 999, height: 42, padding: "0 18px", fontSize: 13 }}
              >
                {option.label}
              </button>
            ))}
            <SpecularButton
              {...specularPrimary}
              radius={999}
              onClick={() => setShowFindModal(true)}
              style={{ height: 42, padding: "0 20px", fontSize: 13, fontWeight: 600 }}
            >
              <Radar style={{ width: 15, height: 15 }} />
              Find More
            </SpecularButton>
          </div>
        </div>

        {/* Country filter */}
        <div style={{
          marginTop: 16, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12,
        }}>
          <span style={{
            fontSize: 11, letterSpacing: ".1em", textTransform: "uppercase", fontWeight: 600,
            color: "color-mix(in srgb, var(--color-text) 45%, transparent)",
          }}>
            Country
          </span>
          <div style={{ position: "relative", display: "inline-block" }}>
            <button
              type="button"
              onClick={() => setCountryDropdownOpen((v) => !v)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                fontFamily: "var(--font-body)",
                fontSize: 13,
                fontWeight: 500,
                color: "var(--color-text)",
                background: "var(--color-neutral-100)",
                border: "1px solid var(--color-divider)",
                borderRadius: 999,
                height: 36,
                padding: "0 36px 0 16px",
                cursor: "pointer",
                minWidth: 140,
                outline: countryDropdownOpen ? "2px solid var(--color-accent)" : "none",
                outlineOffset: -1,
              }}
            >
              {currentCountry === "all" ? "All countries" : currentCountry}
            </button>
            <ChevronDown
              style={{
                position: "absolute",
                right: 12,
                top: "50%",
                transform: countryDropdownOpen
                  ? "translateY(-50%) rotate(180deg)"
                  : "translateY(-50%)",
                width: 14,
                height: 14,
                pointerEvents: "none",
                color: "color-mix(in srgb, var(--color-text) 45%, transparent)",
                transition: "transform 0.2s",
              }}
            />
            {countryDropdownOpen && (
              <>
                <div
                  style={{
                    position: "fixed",
                    inset: 0,
                    zIndex: 40,
                  }}
                  onClick={() => setCountryDropdownOpen(false)}
                />
                <div
                  className="bw-scroll"
                  style={{
                    position: "absolute",
                    top: "calc(100% + 6px)",
                    left: 0,
                    zIndex: 41,
                    minWidth: 200,
                    maxHeight: 280,
                    overflowY: "auto",
                    background: "var(--color-neutral-100)",
                    border: "1px solid var(--color-divider)",
                    borderRadius: "var(--radius-lg)",
                    boxShadow: "var(--shadow-md)",
                    padding: 8,
                    display: "flex",
                    flexDirection: "column",
                    gap: 4,
                  }}
                >
                  {countryOptions.map((country) => {
                    const isActive = currentCountry === country;
                    return (
                      <button
                        key={country}
                        type="button"
                        onClick={() => {
                          handleCountryChange(country);
                          setCountryDropdownOpen(false);
                        }}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontFamily: "var(--font-body)",
                          fontSize: 13,
                          fontWeight: isActive ? 600 : 500,
                          color: isActive ? "var(--color-bg)" : "var(--color-text)",
                          background: isActive ? "var(--color-accent)" : "transparent",
                          border: "1px solid var(--color-divider)",
                          borderRadius: 999,
                          padding: "6px 16px",
                          cursor: "pointer",
                          whiteSpace: "nowrap",
                          transition: "background 0.12s, color 0.12s",
                        }}
                        onMouseEnter={(e) => {
                          if (!isActive) {
                            e.currentTarget.style.background =
                              "color-mix(in srgb, var(--color-text) 7%, transparent)";
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (!isActive) {
                            e.currentTarget.style.background = "transparent";
                          }
                        }}
                      >
                        {country === "all" ? "All countries" : country}
                      </button>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        </div>

        {/* Table */}
        <div style={{ marginTop: 22, paddingBottom: 96 }}>
          <div style={{
            background: "color-mix(in srgb, var(--color-neutral-100) 92%, transparent)",
            borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-sm)",
            padding: "6px 30px 18px", position: "relative",
          }}>
            {isPending && (
              <div style={{
                position: "absolute", inset: 0, zIndex: 10,
                display: "flex", alignItems: "center", justifyContent: "center",
                background: "color-mix(in srgb, var(--color-bg) 60%, transparent)",
                backdropFilter: "blur(4px)", borderRadius: "var(--radius-lg)",
              }}>
                <Loader2 style={{ width: 20, height: 20, animation: "spin 1s linear infinite", color: "var(--color-neutral-500)" }} />
              </div>
            )}
            <table className="bw-table">
              <thead>
                <tr>
                  <th style={{ padding: "20px 14px 14px 0", width: "34%" }}>Company</th>
                  <th style={{ padding: "20px 14px 14px" }}>Exposure tier</th>
                  <th style={{ padding: "20px 14px 14px" }}>Signals</th>
                  <th style={{ padding: "20px 14px 14px" }}>Findings</th>
                  <th style={{ padding: "20px 0 14px 14px", textAlign: "right" }}>Est. exposure</th>
                </tr>
              </thead>
              <tbody>
                {companies.length === 0 && !isPending ? (
                  <tr>
                    <td colSpan={5} style={{ padding: "64px 4px", maxWidth: "46ch" }}>
                      <p style={{ margin: 0, fontFamily: "var(--font-heading)", fontSize: 24 }}>Nothing matches that</p>
                      <p style={{
                        margin: "10px 0 20px", fontSize: 15, lineHeight: 1.6,
                        color: "color-mix(in srgb, var(--color-text) 62%, transparent)",
                      }}>
                        Try a shorter search, or widen the country and tier filters.
                      </p>
                      <button
                        className="bw-btn bw-btn-secondary"
                        onClick={handleClearFilters}
                        style={{ borderRadius: 999, height: 42, padding: "0 20px", fontSize: 13 }}
                      >
                        Clear filters
                      </button>
                    </td>
                  </tr>
                ) : (
                  companies.map((company) => {
                    const exposure = computeEstimatedExposure(company.max_epss, ibmBreachCost);
                    const style = badgeStyle(company.tier);
                    const cveCount = company.cve_count ?? 0;
                    return (
                      <tr
                        key={company.company}
                        onClick={() => router.push(`/companies/${encodeURIComponent(company.company)}`)}
                      >
                        <td style={{ padding: "22px 14px 22px 0", width: "34%" }}>
                          <div style={{ fontSize: 17, fontWeight: 600, letterSpacing: "-.01em" }}>
                            {company.company}
                          </div>
                          <div style={{
                            fontSize: 13, marginTop: 4,
                            color: "color-mix(in srgb, var(--color-text) 52%, transparent)",
                          }}>
                            {company.country ?? "Unknown"}
                          </div>
                        </td>
                        <td style={{ padding: "22px 14px" }}>
                          <span style={{
                            display: "inline-flex", alignItems: "center", lineHeight: 1,
                            borderRadius: 999, fontWeight: 600, whiteSpace: "nowrap",
                            padding: "6px 14px", fontSize: 12,
                            background: style.background, color: style.color, border: style.border,
                          }}>
                            {company.tier ?? "Low"}
                          </span>
                        </td>
                        <td style={{
                          padding: "22px 14px", fontSize: 13,
                          color: "color-mix(in srgb, var(--color-text) 58%, transparent)",
                        }}>
                          {buildSignals(company)}
                        </td>
                        <td style={{
                          padding: "22px 14px", fontSize: 14,
                          color: "color-mix(in srgb, var(--color-text) 72%, transparent)",
                        }}>
                          {cveCount} {cveCount === 1 ? "vulnerability" : "vulnerabilities"}
                        </td>
                        <td style={{
                          padding: "22px 0 22px 14px", textAlign: "right",
                          fontSize: 17, fontWeight: 600, fontVariantNumeric: "tabular-nums",
                        }}>
                          {exposure !== null ? formatCurrencyShort(exposure) : "—"}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{
              marginTop: 20, padding: "0 4px",
              display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12,
            }}>
              <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
                <button
                  className="bw-btn bw-btn-secondary"
                  onClick={() => handlePageChange(currentPage - 1)}
                  disabled={currentPage <= 1 || isPending}
                  style={{ borderRadius: 999, height: 38, padding: "0 16px", fontSize: 13 }}
                >
                  Previous
                </button>
                {pageRange.map((page, index) =>
                  page === "…" ? (
                    <span key={`ellipsis-${index}`} style={{ fontSize: 13, color: "color-mix(in srgb, var(--color-text) 45%, transparent)", padding: "0 2px" }}>…</span>
                  ) : (
                    <button
                      key={page}
                      className="bw-btn"
                      onClick={() => handlePageChange(page)}
                      disabled={isPending}
                      style={{
                        borderRadius: 999, height: 38, width: 38, padding: 0, fontSize: 13,
                        justifyContent: "center",
                        background: page === currentPage ? "var(--color-accent)" : "transparent",
                        color: page === currentPage ? "var(--color-bg)" : "var(--color-text)",
                        border: page === currentPage ? "1px solid var(--color-accent)" : "1px solid var(--color-divider)",
                        fontWeight: page === currentPage ? 700 : 400,
                      }}
                    >
                      {page}
                    </button>
                  )
                )}
                <button
                  className="bw-btn bw-btn-secondary"
                  onClick={() => handlePageChange(currentPage + 1)}
                  disabled={currentPage >= totalPages || isPending}
                  style={{ borderRadius: 999, height: 38, padding: "0 16px", fontSize: 13 }}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Find More Companies modal */}
      {showFindModal && (
        <div className="bw-dialog-backdrop" onClick={handleCloseFindModal}>
          <div
            className="bw-dialog"
            style={{ width: "100%", maxWidth: 440, padding: 0, animation: "bwRise .22s ease-out" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ padding: "30px 34px 20px", display: "flex", alignItems: "flex-start", gap: 16 }}>
              <div style={{ marginRight: "auto" }}>
                <h2 style={{ margin: 0, fontFamily: "var(--font-heading)", fontSize: 27 }}>
                  Find More Companies
                </h2>
                <p style={{
                  margin: "7px 0 0", fontSize: 14,
                  color: "color-mix(in srgb, var(--color-text) 55%, transparent)",
                }}>
                  Query the Shodan API, run the cleaning pipeline, and upsert new companies.
                </p>
              </div>
              <button
                className="bw-btn bw-btn-secondary"
                onClick={handleCloseFindModal}
                disabled={isFinding}
                style={{ borderRadius: 999, width: 36, height: 36, fontSize: 16, flex: "none", padding: 0 }}
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>

            <div style={{ padding: "0 34px 8px" }}>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: "block", fontSize: 11, letterSpacing: ".09em", textTransform: "uppercase", fontWeight: 600, marginBottom: 5, color: "color-mix(in srgb, var(--color-text) 70%, transparent)" }}>
                  Country
                </label>
                <input
                  className="bw-input"
                  placeholder="e.g. DE, US, JP"
                  value={findCountry}
                  onChange={(e) => setFindCountry(e.target.value)}
                  disabled={isFinding}
                  style={{ height: 44, borderRadius: "var(--radius-md)" }}
                />
              </div>
              <div style={{ marginBottom: 8 }}>
                <label style={{ display: "block", fontSize: 11, letterSpacing: ".09em", textTransform: "uppercase", fontWeight: 600, marginBottom: 5, color: "color-mix(in srgb, var(--color-text) 70%, transparent)" }}>
                  Product / Keyword
                </label>
                <input
                  className="bw-input"
                  placeholder="e.g. nginx, Apache, OpenSSH"
                  value={findProduct}
                  onChange={(e) => setFindProduct(e.target.value)}
                  disabled={isFinding}
                  style={{ height: 44, borderRadius: "var(--radius-md)" }}
                />
              </div>
              <p style={{ margin: "12px 0 0", fontSize: 13, color: "color-mix(in srgb, var(--color-text) 50%, transparent)" }}>
                At least one field is required. Uses 1 Shodan API credit per query (max 100 results).
              </p>
            </div>

            {findError && (
              <div style={{ margin: "0 34px", padding: "12px 16px", borderRadius: "var(--radius-md)", background: "color-mix(in srgb, #b42318 8%, transparent)", fontSize: 14, color: "#b42318" }}>
                {findError}
              </div>
            )}

            {findResult && (
              <div style={{ margin: "0 34px", padding: "12px 16px", borderRadius: "var(--radius-md)", background: "color-mix(in srgb, var(--color-accent-2-500) 12%, transparent)", fontSize: 14, color: "var(--color-accent-2-800)" }}>
                {findResult}
              </div>
            )}

            {foundCompanies.length > 0 && (
              <div style={{ margin: "14px 34px 0" }}>
                <p style={{
                  margin: "0 0 8px", fontSize: 11, letterSpacing: "0.09em",
                  textTransform: "uppercase", fontWeight: 600,
                  color: "color-mix(in srgb, var(--color-text) 48%, transparent)",
                }}>
                  Companies found — worst first
                </p>
                <div className="bw-scroll" style={{
                  maxHeight: 232, overflowY: "auto",
                  border: "1px solid var(--color-divider)",
                  borderRadius: "var(--radius-md)",
                }}>
                  {foundCompanies.map((found, index) => (
                    <button
                      key={found.company}
                      onClick={() => router.push(`/companies/${encodeURIComponent(found.company)}`)}
                      style={{
                        display: "flex", alignItems: "center", gap: 12, width: "100%",
                        padding: "11px 14px", background: "transparent", cursor: "pointer",
                        textAlign: "left", font: "inherit", fontSize: 14,
                        border: "none",
                        borderTop: index === 0 ? "none" : "1px solid color-mix(in srgb, var(--color-text) 8%, transparent)",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "color-mix(in srgb, var(--color-text) 5%, transparent)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    >
                      <span style={{ fontWeight: 600, marginRight: "auto" }}>
                        {found.company}
                        {found.country && (
                          <span style={{
                            fontWeight: 400, fontSize: 12,
                            color: "color-mix(in srgb, var(--color-text) 50%, transparent)",
                          }}>
                            {" · "}{found.country}
                          </span>
                        )}
                      </span>
                      <span style={{
                        fontSize: 12,
                        color: "color-mix(in srgb, var(--color-text) 55%, transparent)",
                        whiteSpace: "nowrap",
                      }}>
                        {found.cveCount} {found.cveCount === 1 ? "vuln" : "vulns"}
                      </span>
                      <span style={{
                        display: "inline-flex", alignItems: "center", lineHeight: 1,
                        borderRadius: 999, fontWeight: 600, whiteSpace: "nowrap",
                        padding: "5px 12px", fontSize: 11,
                        ...badgeStyle(found.tier),
                      }}>
                        {found.tier}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div style={{
              padding: "22px 34px 28px", display: "flex", alignItems: "center", gap: 10,
              borderTop: "1px solid var(--color-divider)", marginTop: 18,
            }}>
              <button
                className="bw-btn bw-btn-secondary"
                onClick={handleCloseFindModal}
                disabled={isFinding}
                style={{ borderRadius: 999, height: 42, padding: "0 20px", fontSize: 13 }}
              >
                {findResult ? "Done" : "Cancel"}
              </button>
              <SpecularButton
                {...specularPrimary}
                radius={999}
                onClick={handleFindCompanies}
                disabled={isFinding || (!findCountry && !findProduct)}
                style={{ marginLeft: "auto", height: 42, padding: "0 26px", fontSize: 14, fontWeight: 600 }}
              >
                {isFinding ? (
                  <>
                    <Loader2 style={{ width: 16, height: 16, animation: "spin 1s linear infinite" }} />
                    Searching Shodan...
                  </>
                ) : (
                  <>
                    <Radar style={{ width: 16, height: 16 }} />
                    Run Pipeline
                  </>
                )}
              </SpecularButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
