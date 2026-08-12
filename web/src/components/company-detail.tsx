"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  TIER_BADGE_STYLES,
  describeVulnerability,
  formatCurrency,
  formatCvss,
  formatEpss,
} from "@/lib/constants";
import type { Company, CompanyVuln } from "@/lib/types";
import { DotField } from "@/components/dot-field";
import { GlassTile } from "@/components/glass-icons";
import { SpecularButton, specularPrimary, specularSecondary } from "@/components/specular-button";
import { useTypewriter } from "@/lib/use-typewriter";
import { RANK_LABELS, type RankedContact } from "@/lib/contacts";
import { Loader2, X, Phone } from "lucide-react";

interface CompanyDetailProps {
  company: Company;
  vulns: CompanyVuln[];
  ibmBreachCost: number;
  estimatedExposure: number | null;
}

/**
 * Every glass panel on this screen uses one neutral tint. Keying it to the tier
 * put red behind the exposure figure and the exploited findings, which read as
 * alarm colour competing with the Critical badge — the badge is the only place
 * red should carry meaning.
 */
const GLASS_TINT = "#6a6a68";

function badgeStyle(tier: string | null, big: boolean): React.CSSProperties {
  const t = TIER_BADGE_STYLES[tier ?? "Low"] ?? TIER_BADGE_STYLES.Low;
  return {
    ...t,
    display: "inline-flex",
    alignItems: "center",
    lineHeight: 1,
    borderRadius: 999,
    fontWeight: 600,
    whiteSpace: "nowrap",
    padding: big ? "9px 20px" : "6px 14px",
    fontSize: big ? 14 : 12,
  };
}

function buildVerdict(company: Company): string {
  const pct = Math.round((company.max_epss ?? 0) * 100);
  if (company.ransomware)
    return "A flaw on their systems is being exploited right now, and it is one ransomware groups are known to use.";
  if (company.in_kev)
    return "A flaw on their systems is confirmed under active attack in the wild today.";
  if (company.tier === "High")
    return `Nothing confirmed exploited yet. The worst flaw here carries a ${pct}% chance of being attacked in the next 30 days.`;
  if (company.tier === "Medium")
    return `Real risk rather than an emergency: the worst flaw sits at a ${pct}% chance of attack in the next 30 days.`;
  return "No urgent exposure. Worth a light touch, not a priority call.";
}

export function CompanyDetail({
  company,
  vulns,
  ibmBreachCost,
  estimatedExposure,
}: CompanyDetailProps) {
  const router = useRouter();
  const [emailOpen, setEmailOpen] = useState(false);
  const [emailGenerating, setEmailGenerating] = useState(false);
  const [emailContent, setEmailContent] = useState("");
  const [emailError, setEmailError] = useState<string | null>(null);
  const [isCopied, setIsCopied] = useState(false);
  const [contactsOpen, setContactsOpen] = useState(false);
  const [contactsLoading, setContactsLoading] = useState(false);
  const [contacts, setContacts] = useState<RankedContact[]>([]);
  const [contactsMeta, setContactsMeta] = useState<{ organization: string | null; totalFound: number } | null>(null);
  const [contactsError, setContactsError] = useState<string | null>(null);
  const [hookOpen, setHookOpen] = useState(false);
  const [hookLoading, setHookLoading] = useState(false);
  const [hookText, setHookText] = useState("");
  const [hookError, setHookError] = useState<string | null>(null);

  useEffect(() => {
    function handleEsc(e: KeyboardEvent) {
      if (e.key === "Escape") setEmailOpen(false);
    }
    document.addEventListener("keydown", handleEsc);
    return () => document.removeEventListener("keydown", handleEsc);
  }, []);

  async function handleOpenEmail() {
    setEmailOpen(true);
    setEmailGenerating(true);
    setEmailError(null);
    setEmailContent("");

    try {
      const response = await fetch("/api/generate-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company: company.company,
          country: company.country,
          tier: company.tier,
          inKev: company.in_kev,
          ransomware: company.ransomware,
          cveCount: company.cve_count,
          maxCvss: company.max_cvss,
          maxEpss: company.max_epss,
          estimatedExposure,
          ibmBreachCost,
          vulns: vulns.map((vuln) => ({
            cveId: vuln.cve_id,
            cvss: vuln.cvss,
            epss: vuln.epss,
            title: describeVulnerability(vuln.summary),
            summary: vuln.summary,
            inKev: vuln.in_kev,
            ransomware: vuln.ransomware,
          })),
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error ?? "Failed to generate email");
      }

      const data = await response.json();
      setEmailContent(data.email);
    } catch (error) {
      setEmailError(
        error instanceof Error ? error.message : "Something went wrong"
      );
    } finally {
      setEmailGenerating(false);
    }
  }

  async function handleOpenHook() {
    setHookOpen(true);
    setHookLoading(true);
    setHookError(null);
    setHookText("");

    try {
      const response = await fetch("/api/generate-hook", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company: company.company,
          tier: company.tier,
          inKev: company.in_kev,
          ransomware: company.ransomware,
          maxEpss: company.max_epss,
          cveCount: company.cve_count,
          estimatedExposure,
          ibmBreachCost,
          topFinding: sortedVulns[0]
            ? describeVulnerability(sortedVulns[0].summary)
            : null,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? "Failed to generate hook");
      setHookText(data.hook ?? "");
    } catch (error) {
      setHookError(error instanceof Error ? error.message : "Something went wrong");
    } finally {
      setHookLoading(false);
    }
  }

  async function handleOpenContacts() {
    setContactsOpen(true);
    setContactsLoading(true);
    setContactsError(null);
    setContacts([]);
    setContactsMeta(null);

    try {
      const response = await fetch("/api/contacts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ company: company.company }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? "Failed to look up contacts");

      setContacts(data.contacts ?? []);
      setContactsMeta({
        organization: data.organization ?? null,
        totalFound: data.totalFound ?? 0,
      });
    } catch (error) {
      setContactsError(
        error instanceof Error ? error.message : "Something went wrong"
      );
    } finally {
      setContactsLoading(false);
    }
  }

  async function handleCopyEmail() {
    if (!emailContent) return;
    await navigator.clipboard.writeText(emailContent);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 1600);
  }

  // Idles harmlessly while hookText is empty, so it can sit unconditionally
  // at the top level rather than inside the modal branch.
  const { revealed: hookRevealed, isTyping: hookTyping } = useTypewriter(hookText);

  const pct = Math.round((company.max_epss ?? 0) * 100);
  const cveCount = company.cve_count ?? 0;
  const exposureBasis = `IBM average breach cost (${formatCurrency(ibmBreachCost)}) × ${pct}% probability of attack in the next 30 days. Computed in code, shown as an estimate.`;
  const verdict = buildVerdict(company);
  const sortedVulns = [...vulns].sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0));

  return (
    <div style={{ minHeight: "100vh", background: "var(--color-bg)", position: "relative", isolation: "isolate" }}>
      {/* DotField background */}
      <div aria-hidden style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(1100px 520px at 10% -10%, rgba(198, 113, 57, 0.04), transparent 70%), radial-gradient(900px 460px at 90% 2%, rgba(122, 138, 94, 0.03), transparent 72%), radial-gradient(1300px 620px at 50% 112%, rgba(255, 255, 255, 0.6), transparent 70%)",
        }} />
        {/* Denser and darker than the list screen's field: these dots are read
            through frosted panels, and the stock values all but vanish. */}
        <DotField
          dotSpacing={13}
          dotRadius={2}
          gradientFrom="rgba(26, 26, 26, 0.42)"
          gradientTo="rgba(26, 26, 26, 0.16)"
        />
      </div>

      {/* Nav bar */}
      <div style={{
        position: "sticky", top: 0, zIndex: 20,
        borderBottom: "1px solid color-mix(in srgb, var(--color-text) 7%, transparent)",
        background: "color-mix(in srgb, var(--color-bg) 74%, transparent)",
        backdropFilter: "blur(14px)", WebkitBackdropFilter: "blur(14px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 24, padding: "18px clamp(24px, 3.5vw, 64px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginRight: "auto", cursor: "pointer" }} onClick={() => router.push("/")}>
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

      {/* Detail content */}
      <div style={{
        position: "relative", zIndex: 1, maxWidth: 1120, margin: "0 auto",
        padding: "34px clamp(24px, 3.5vw, 64px) 96px",
      }}>
        <button
          className="bw-btn bw-btn-ghost"
          onClick={() => router.push("/")}
          style={{ borderRadius: 999, height: 36, padding: "0 12px 0 8px", fontSize: 13, marginLeft: -8 }}
        >
          ← All prospects
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 26, flexWrap: "wrap" }}>
          <h1 style={{
            margin: 0, fontFamily: "var(--font-heading)", fontWeight: 400,
            fontSize: 46, lineHeight: 1.05, letterSpacing: "-.01em",
          }}>
            {company.company}
          </h1>
          <span style={badgeStyle(company.tier, true)}>{company.tier ?? "Low"}</span>
        </div>
        <p style={{
          margin: "12px 0 0", fontSize: 15,
          color: "color-mix(in srgb, var(--color-text) 58%, transparent)",
        }}>
          {company.country ?? "Unknown"} · {cveCount} {cveCount === 1 ? "distinct vulnerability" : "distinct vulnerabilities"}
        </p>

        {/* Exposure card */}
        <div
          className="bw-glass bw-glass-tint bw-glass-hover"
          style={{
            marginTop: 34, padding: "38px 40px 34px", overflow: "hidden",
            "--glass-tint": GLASS_TINT,
          } as React.CSSProperties}
        >
          <span style={{
            position: "absolute", right: -60, bottom: -90,
            width: 300, height: 300, borderRadius: 999,
            background: "color-mix(in srgb, var(--color-accent-200) 30%, transparent)",
            pointerEvents: "none",
          }} />
          <div style={{ position: "relative" }}>
            <p style={{
              margin: 0, fontSize: 12, letterSpacing: ".12em", textTransform: "uppercase",
              fontWeight: 600, color: "var(--color-accent-700)",
            }}>
              Estimated exposure
            </p>
            <p style={{
              margin: "10px 0 0", fontFamily: "var(--font-heading)", fontWeight: 400,
              fontSize: 76, lineHeight: 1, letterSpacing: "-.02em", fontVariantNumeric: "tabular-nums",
            }}>
              {estimatedExposure !== null ? formatCurrency(estimatedExposure) : "—"}
            </p>
            <p style={{
              margin: "14px 0 0", fontSize: 13, lineHeight: 1.6, maxWidth: "62ch",
              color: "color-mix(in srgb, var(--color-text) 58%, transparent)",
            }}>
              {exposureBasis}
            </p>

            <p style={{
              margin: "26px 0 0", fontSize: 20, lineHeight: 1.45, maxWidth: "46ch", fontWeight: 500,
            }}>
              {verdict}
            </p>

            {/* Gap clears the two specular canvases, which each extend 20px
                past their button and would otherwise overlap. */}
            <div style={{ display: "flex", gap: 22, marginTop: 28, flexWrap: "wrap" }}>
              <SpecularButton
                {...specularPrimary}
                radius={999}
                onClick={handleOpenEmail}
                disabled={emailGenerating}
                style={{ height: 48, padding: "0 28px", fontSize: 15, fontWeight: 600 }}
              >
                {emailGenerating ? (
                  <>
                    <Loader2 style={{ width: 18, height: 18, animation: "spin 1s linear infinite" }} />
                    Writing...
                  </>
                ) : (
                  "Outreach email"
                )}
              </SpecularButton>

              <SpecularButton
                {...specularPrimary}
                radius={999}
                onClick={handleOpenContacts}
                disabled={contactsLoading}
                style={{ height: 48, padding: "0 28px", fontSize: 15, fontWeight: 600 }}
              >
                {contactsLoading ? (
                  <>
                    <Loader2 style={{ width: 18, height: 18, animation: "spin 1s linear infinite" }} />
                    Looking up...
                  </>
                ) : (
                  "Contact Info"
                )}
              </SpecularButton>

              {/* Same component and shape as its two siblings so the row reads as
                  one set, but the light specular treatment marks it as the
                  different kind of action: something you say, not something you send. */}
              <SpecularButton
                {...specularSecondary}
                radius={999}
                onClick={handleOpenHook}
                disabled={hookLoading}
                style={{
                  height: 48, padding: "0 28px", fontSize: 15, fontWeight: 600,
                  border: "1px solid var(--color-divider)",
                }}
              >
                {hookLoading ? (
                  <>
                    <Loader2 style={{ width: 18, height: 18, animation: "spin 1s linear infinite" }} />
                    Thinking...
                  </>
                ) : (
                  <>
                    <Phone style={{ width: 16, height: 16 }} />
                    Generate a Hook
                  </>
                )}
              </SpecularButton>
            </div>
          </div>
        </div>

        {/* Fact cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginTop: 14 }}>
          <div className="bw-glass" style={{ borderRadius: "var(--radius-md)", padding: "20px 22px" }}>
            <p style={{
              margin: 0, fontSize: 12, letterSpacing: ".1em", textTransform: "uppercase", fontWeight: 600,
              color: "color-mix(in srgb, var(--color-text) 48%, transparent)",
            }}>
              Actively exploited
            </p>
            <p style={{ margin: "8px 0 0", fontSize: 19, fontWeight: 600 }}>
              {company.in_kev ? "Yes, on the CISA list" : "Not confirmed"}
            </p>
          </div>
          <div className="bw-glass" style={{ borderRadius: "var(--radius-md)", padding: "20px 22px" }}>
            <p style={{
              margin: 0, fontSize: 12, letterSpacing: ".1em", textTransform: "uppercase", fontWeight: 600,
              color: "color-mix(in srgb, var(--color-text) 48%, transparent)",
            }}>
              Ransomware-linked
            </p>
            <p style={{ margin: "8px 0 0", fontSize: 19, fontWeight: 600 }}>
              {company.ransomware ? "Yes" : "No"}
            </p>
          </div>
          <div className="bw-glass" style={{ borderRadius: "var(--radius-md)", padding: "20px 22px" }}>
            <p style={{
              margin: 0, fontSize: 12, letterSpacing: ".1em", textTransform: "uppercase", fontWeight: 600,
              color: "color-mix(in srgb, var(--color-text) 48%, transparent)",
            }}>
              Worst severity
            </p>
            <p style={{ margin: "8px 0 0", fontSize: 19, fontWeight: 600 }}>
              {formatCvss(company.max_cvss)}
            </p>
          </div>
        </div>

        {/* Findings */}
        <h2 style={{ margin: "52px 0 6px", fontFamily: "var(--font-heading)", fontWeight: 400, fontSize: 30 }}>
          What we can see from the outside
        </h2>
        <p style={{
          margin: "0 0 26px", fontSize: 15, lineHeight: 1.6, maxWidth: "60ch",
          color: "color-mix(in srgb, var(--color-text) 62%, transparent)",
        }}>
          Worst findings first, by the measured probability of attack in the next 30 days.
        </p>

        {sortedVulns.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {sortedVulns.map((vuln, index) => (
              <div
                key={`${vuln.cve_id}-${index}`}
                className="bw-glass bw-glass-tint bw-glass-hover"
                style={{
                  padding: "28px 32px", display: "grid",
                  gridTemplateColumns: "52px 1fr", gap: 22, alignItems: "start",
                  // Clipped, or ten stacked tints bleed into one wash down the column.
                  overflow: "hidden",
                  "--glass-tint": GLASS_TINT,
                  "--glass-tint-opacity": 0.1,
                } as React.CSSProperties}
              >
                <GlassTile color="ink">
                  <span style={{ fontSize: 15, fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>
                    {String(index + 1).padStart(2, "0")}
                  </span>
                </GlassTile>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                    <h3 style={{
                      margin: 0, fontFamily: "var(--font-heading)", fontWeight: 400,
                      fontSize: 22, lineHeight: 1.2,
                    }}>
                      {describeVulnerability(vuln.summary)}
                    </h3>
                    {vuln.in_kev && (
                      <span className="bw-tag" style={{
                        background: "var(--color-accent)", color: "var(--color-bg)",
                        borderRadius: 999, padding: "4px 12px", fontSize: 11, fontWeight: 600,
                      }}>
                        Exploited in the wild
                      </span>
                    )}
                    {vuln.ransomware && (
                      <span className="bw-tag" style={{
                        background: "transparent", border: "1px solid var(--color-divider)",
                        color: "var(--color-neutral-700)",
                        borderRadius: 999, padding: "3px 12px", fontSize: 11, fontWeight: 600,
                      }}>
                        Ransomware
                      </span>
                    )}
                  </div>
                  {vuln.summary && (
                    <p style={{
                      margin: "12px 0 0", fontSize: 16, lineHeight: 1.62, maxWidth: "66ch", textWrap: "pretty",
                    }}>
                      {vuln.summary}
                    </p>
                  )}
                  <div style={{
                    display: "flex", flexWrap: "wrap", gap: 28, marginTop: 20, paddingTop: 18,
                    borderTop: "1px solid color-mix(in srgb, var(--color-text) 10%, transparent)",
                  }}>
                    <div>
                      <p style={{
                        margin: 0, fontSize: 11, letterSpacing: ".09em", textTransform: "uppercase", fontWeight: 600,
                        color: "color-mix(in srgb, var(--color-text) 48%, transparent)",
                      }}>
                        Attack probability, 30 days
                      </p>
                      <p style={{ margin: "5px 0 0", fontSize: 16, fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>
                        {formatEpss(vuln.epss)}
                      </p>
                    </div>
                    <div>
                      <p style={{
                        margin: 0, fontSize: 11, letterSpacing: ".09em", textTransform: "uppercase", fontWeight: 600,
                        color: "color-mix(in srgb, var(--color-text) 48%, transparent)",
                      }}>
                        Severity
                      </p>
                      <p style={{ margin: "5px 0 0", fontSize: 16, fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>
                        {formatCvss(vuln.cvss)}
                      </p>
                    </div>
                    <div>
                      <p style={{
                        margin: 0, fontSize: 11, letterSpacing: ".09em", textTransform: "uppercase", fontWeight: 600,
                        color: "color-mix(in srgb, var(--color-text) 48%, transparent)",
                      }}>
                        Reference
                      </p>
                      <p style={{
                        margin: "5px 0 0", fontSize: 16, fontWeight: 500, fontVariantNumeric: "tabular-nums",
                        color: "color-mix(in srgb, var(--color-text) 62%, transparent)",
                      }}>
                        {vuln.cve_id}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{
            background: "var(--color-surface)", borderRadius: "var(--radius-lg)", padding: "48px 32px",
            textAlign: "center",
          }}>
            <p style={{ fontFamily: "var(--font-heading)", fontSize: 24, margin: 0 }}>No findings yet</p>
            <p style={{
              margin: "10px 0 0", fontSize: 15, lineHeight: 1.6,
              color: "color-mix(in srgb, var(--color-text) 62%, transparent)",
            }}>
              Run the pipeline to populate per-CVE findings for this company.
            </p>
          </div>
        )}
      </div>

      {/* Email modal */}
      {emailOpen && (
        <div className="bw-dialog-backdrop" onClick={() => !emailGenerating && setEmailOpen(false)}>
          <div
            className="bw-dialog"
            style={{
              width: "100%", maxWidth: 680, maxHeight: "88vh",
              display: "flex", flexDirection: "column", overflow: "hidden",
              animation: "bwRise .22s ease-out",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ padding: "30px 34px 20px", display: "flex", alignItems: "flex-start", gap: 16 }}>
              <div style={{ marginRight: "auto" }}>
                <h2 style={{ margin: 0, fontFamily: "var(--font-heading)", fontSize: 27 }}>
                  Outreach email
                </h2>
                <p style={{
                  margin: "7px 0 0", fontSize: 14,
                  color: "color-mix(in srgb, var(--color-text) 55%, transparent)",
                }}>
                  {company.company} · drafted from their {Math.min(vulns.length, 5)} worst findings
                </p>
              </div>
              <button
                className="bw-btn bw-btn-secondary"
                onClick={() => !emailGenerating && setEmailOpen(false)}
                disabled={emailGenerating}
                style={{ borderRadius: 999, width: 36, height: 36, fontSize: 16, flex: "none", padding: 0 }}
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>

            {emailGenerating && (
              <div style={{ padding: "8px 34px 40px" }}>
                <p style={{
                  margin: "0 0 22px", fontSize: 14,
                  color: "color-mix(in srgb, var(--color-text) 55%, transparent)",
                }}>
                  Writing from this company&apos;s findings…
                </p>
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {[62, 94, 88, 40].map((width, i) => (
                    <span key={i} style={{
                      height: 15, width: `${width}%`, borderRadius: 999,
                      background: "var(--color-neutral-300)",
                      animation: `bwShimmer 1.1s ease-in-out ${i * 0.12}s infinite`,
                    }} />
                  ))}
                </div>
              </div>
            )}

            {!emailGenerating && emailError && (
              <div style={{ padding: "8px 34px 40px" }}>
                <div style={{
                  padding: "12px 16px", borderRadius: "var(--radius-md)",
                  background: "color-mix(in srgb, #b42318 8%, transparent)",
                  fontSize: 14, color: "#b42318",
                }}>
                  {emailError}
                </div>
              </div>
            )}

            {!emailGenerating && !emailError && emailContent && (
              <>
                <div style={{ padding: "0 34px 8px", overflowY: "auto", flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
                  <div style={{ marginBottom: 16 }}>
                    <label style={{
                      display: "block", fontSize: 11, letterSpacing: ".09em", textTransform: "uppercase",
                      fontWeight: 600, marginBottom: 5,
                      color: "color-mix(in srgb, var(--color-text) 70%, transparent)",
                    }}>
                      Body
                    </label>
                    <textarea
                      className="bw-input"
                      value={emailContent}
                      onChange={(e) => setEmailContent(e.target.value)}
                      style={{
                        minHeight: 220, borderRadius: "var(--radius-md)", fontSize: 15,
                        lineHeight: 1.65, padding: "16px 18px",
                        background: "var(--color-neutral-100)",
                      }}
                    />
                  </div>
                  <p style={{
                    margin: "16px 0 0", fontSize: 13, lineHeight: 1.6, display: "flex", gap: 10,
                    color: "color-mix(in srgb, var(--color-text) 58%, transparent)",
                  }}>
                    <span style={{
                      width: 8, height: 8, borderRadius: 999, background: "var(--color-accent-2-500)",
                      flex: "none", marginTop: 6,
                    }} />
                    <span>Every figure here was computed in code from this company&apos;s own records and passed in. The model phrases them, it never invents a number.</span>
                  </p>
                </div>

                <div style={{
                  padding: "22px 34px 28px", display: "flex", alignItems: "center", gap: 10,
                  borderTop: "1px solid var(--color-divider)", marginTop: 18,
                }}>
                  <button
                    className="bw-btn bw-btn-secondary"
                    onClick={handleOpenEmail}
                    style={{ borderRadius: 999, height: 42, padding: "0 20px", fontSize: 13 }}
                  >
                    Rewrite
                  </button>
                  <button
                    className="bw-btn bw-btn-secondary"
                    onClick={handleCopyEmail}
                    style={{ borderRadius: 999, height: 42, padding: "0 20px", fontSize: 13 }}
                  >
                    {isCopied ? "Copied" : "Copy"}
                  </button>
                  <SpecularButton
                    {...specularPrimary}
                    radius={999}
                    onClick={() => setEmailOpen(false)}
                    style={{ marginLeft: "auto", height: 42, padding: "0 26px", fontSize: 14, fontWeight: 600 }}
                  >
                    Done
                  </SpecularButton>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Contact Info modal */}
      {contactsOpen && (
        <div className="bw-dialog-backdrop" onClick={() => !contactsLoading && setContactsOpen(false)}>
          <div
            className="bw-dialog"
            style={{ width: "min(720px, 100%)", maxHeight: "86vh", overflowY: "auto" }}
            onClick={(event) => event.stopPropagation()}
          >
            <div style={{ padding: "30px 34px 20px", display: "flex", alignItems: "flex-start", gap: 16 }}>
              <div style={{ marginRight: "auto" }}>
                <h2 style={{ margin: 0, fontFamily: "var(--font-heading)", fontSize: 27 }}>
                  Contact Info
                </h2>
                <p style={{
                  margin: "7px 0 0", fontSize: 14,
                  color: "color-mix(in srgb, var(--color-text) 55%, transparent)",
                }}>
                  {contactsLoading
                    ? `Searching ${company.company}...`
                    : contactsMeta
                      ? `${contactsMeta.organization ?? company.company} · ${contacts.length} of ${contactsMeta.totalFound} people found`
                      : company.company}
                </p>
              </div>
              <button
                className="bw-btn bw-btn-secondary"
                onClick={() => setContactsOpen(false)}
                style={{ borderRadius: 999, width: 38, height: 38, padding: 0 }}
                aria-label="Close"
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>

            {contactsLoading && (
              <div style={{ padding: "10px 34px 40px", display: "flex", alignItems: "center", gap: 10, fontSize: 14, color: "color-mix(in srgb, var(--color-text) 60%, transparent)" }}>
                <Loader2 style={{ width: 17, height: 17, animation: "spin 1s linear infinite" }} />
                Looking up who owns security at this company...
              </div>
            )}

            {contactsError && (
              <div style={{ margin: "0 34px 28px", padding: "14px 16px", borderRadius: "var(--radius-md)", background: "color-mix(in srgb, #b42318 10%, transparent)", color: "#8a1c12", fontSize: 14, lineHeight: 1.55 }}>
                {contactsError}
              </div>
            )}

            {!contactsLoading && !contactsError && contacts.length === 0 && (
              <div style={{ margin: "0 34px 30px", padding: "26px 20px", borderRadius: "var(--radius-md)", background: "var(--color-surface)", textAlign: "center" }}>
                <p style={{ margin: 0, fontFamily: "var(--font-heading)", fontSize: 19 }}>
                  No contacts found
                </p>
                <p style={{ margin: "8px 0 0", fontSize: 13.5, color: "color-mix(in srgb, var(--color-text) 58%, transparent)" }}>
                  No published email addresses for {company.company}.
                </p>
              </div>
            )}

            {!contactsLoading && contacts.length > 0 && (
              <div style={{ padding: "0 34px", display: "flex", flexDirection: "column", gap: 12 }}>
                {contacts.map((contact) => (
                  <div
                    key={contact.email}
                    style={{
                      border: "1px solid var(--color-divider)",
                      borderRadius: "var(--radius-md)",
                      padding: "16px 18px",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                      <span style={{ fontFamily: "var(--font-heading)", fontSize: 18 }}>
                        {contact.name ?? contact.email}
                      </span>
                      <span className="bw-tag" style={{
                        borderRadius: 999, padding: "4px 12px", fontSize: 11, fontWeight: 600,
                        background: contact.rank === "security" ? "var(--color-accent)" : "transparent",
                        color: contact.rank === "security" ? "var(--color-bg)" : "var(--color-neutral-700)",
                        border: contact.rank === "security" ? "none" : "1px solid var(--color-divider)",
                      }}>
                        {RANK_LABELS[contact.rank]}
                      </span>
                      {contact.downgraded && (
                        <span className="bw-tag" style={{
                          borderRadius: 999, padding: "3px 11px", fontSize: 11, fontWeight: 600,
                          background: "transparent", color: "var(--color-neutral-600)",
                          border: "1px dashed var(--color-divider)",
                        }}>
                          Demoted
                        </span>
                      )}
                    </div>

                    {contact.position && (
                      <p style={{ margin: "6px 0 0", fontSize: 14, color: "color-mix(in srgb, var(--color-text) 70%, transparent)" }}>
                        {contact.position}
                      </p>
                    )}

                    <div style={{ display: "flex", flexWrap: "wrap", gap: 18, marginTop: 12, alignItems: "center" }}>
                      <a
                        href={`mailto:${contact.email}`}
                        style={{ fontSize: 14, fontWeight: 600, color: "var(--color-text)", textDecoration: "underline", textUnderlineOffset: 3 }}
                      >
                        {contact.email}
                      </a>
                      {contact.linkedin && (
                        <a
                          href={contact.linkedin}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ fontSize: 12, color: "color-mix(in srgb, var(--color-text) 52%, transparent)" }}
                        >
                          LinkedIn
                        </a>
                      )}
                    </div>

                    <p style={{ margin: "10px 0 0", fontSize: 12, color: "color-mix(in srgb, var(--color-text) 48%, transparent)" }}>
                      {contact.rankReason}
                    </p>
                  </div>
                ))}
              </div>
            )}

            <div style={{
              padding: "22px 34px 28px", display: "flex", alignItems: "center", gap: 10,
              borderTop: "1px solid var(--color-divider)", marginTop: 18,
            }}>
              <SpecularButton
                {...specularPrimary}
                radius={999}
                onClick={() => setContactsOpen(false)}
                style={{ marginLeft: "auto", height: 42, padding: "0 26px", fontSize: 14, fontWeight: 600 }}
              >
                Done
              </SpecularButton>
            </div>
          </div>
        </div>
      )}
      {/* Generate a Hook — intentionally a small box, not a full dialog. It holds
          three spoken sentences, so it is sized to what a salesperson reads
          aloud rather than to the screen. */}
      {hookOpen && (
        <div className="bw-dialog-backdrop" onClick={() => !hookLoading && setHookOpen(false)}>
          <div
            className="bw-dialog"
            style={{ width: "min(520px, 100%)" }}
            onClick={(event) => event.stopPropagation()}
          >
            <div style={{ padding: "24px 28px 4px", display: "flex", alignItems: "flex-start", gap: 14 }}>
              <div style={{ marginRight: "auto" }}>
                <h2 style={{ margin: 0, fontFamily: "var(--font-heading)", fontSize: 22 }}>
                  Your opening line
                </h2>
                <p style={{
                  margin: "5px 0 0", fontSize: 13,
                  color: "color-mix(in srgb, var(--color-text) 55%, transparent)",
                }}>
                  {company.company} · say this, don&apos;t send it
                </p>
              </div>
              <button
                className="bw-btn bw-btn-secondary"
                onClick={() => setHookOpen(false)}
                style={{ borderRadius: 999, width: 34, height: 34, padding: 0 }}
                aria-label="Close"
              >
                <X style={{ width: 15, height: 15 }} />
              </button>
            </div>

            <div style={{ padding: "14px 28px 4px" }}>
              {hookLoading && (
                <div style={{ display: "flex", alignItems: "center", gap: 9, fontSize: 14, color: "color-mix(in srgb, var(--color-text) 58%, transparent)", minHeight: 92 }}>
                  <Loader2 style={{ width: 16, height: 16, animation: "spin 1s linear infinite" }} />
                  Working out the angle...
                </div>
              )}

              {hookError && (
                <div style={{ padding: "12px 14px", borderRadius: "var(--radius-md)", background: "color-mix(in srgb, #b42318 10%, transparent)", color: "#8a1c12", fontSize: 13.5, lineHeight: 1.55 }}>
                  {hookError}
                </div>
              )}

              {!hookLoading && !hookError && hookText && (
                <p
                  aria-live="polite"
                  style={{
                    margin: 0, minHeight: 92,
                    fontFamily: "var(--font-heading)", fontSize: 19, lineHeight: 1.5,
                    textWrap: "pretty",
                  }}
                >
                  {hookRevealed}
                  {hookTyping && (
                    <span
                      aria-hidden
                      style={{
                        display: "inline-block", width: 2, height: "1.05em",
                        marginLeft: 2, verticalAlign: "-0.15em",
                        background: "var(--color-text)",
                        animation: "bwCaret 1s steps(1) infinite",
                      }}
                    />
                  )}
                </p>
              )}
            </div>

            <div style={{
              padding: "18px 28px 24px", display: "flex", alignItems: "center", gap: 9,
              borderTop: "1px solid var(--color-divider)", marginTop: 16,
            }}>
              <button
                className="bw-btn bw-btn-secondary"
                onClick={handleOpenHook}
                disabled={hookLoading}
                style={{ borderRadius: 999, height: 38, padding: "0 18px", fontSize: 13 }}
              >
                Another angle
              </button>
              <button
                className="bw-btn bw-btn-secondary"
                onClick={async () => {
                  if (!hookText) return;
                  await navigator.clipboard.writeText(hookText);
                  setIsCopied(true);
                  setTimeout(() => setIsCopied(false), 1600);
                }}
                disabled={!hookText || hookLoading}
                style={{ borderRadius: 999, height: 38, padding: "0 18px", fontSize: 13 }}
              >
                {isCopied ? "Copied" : "Copy"}
              </button>
              <SpecularButton
                {...specularPrimary}
                radius={999}
                onClick={() => setHookOpen(false)}
                style={{ marginLeft: "auto", height: 38, padding: "0 22px", fontSize: 13, fontWeight: 600 }}
              >
                Done
              </SpecularButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}