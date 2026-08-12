/**
 * One place to name the Gemini model, used by both the outreach-email route and
 * the pipeline's Layer-3 domain resolution.
 *
 * Pinned deliberately rather than using a `-latest` alias: this app gets demoed,
 * and an alias that silently rolls to a new model can change behaviour between
 * a rehearsal and the real thing. Google retires older models (gemini-2.0-flash
 * returned 404 "no longer available"), so if generation starts failing, list the
 * live models and pin a current one:
 *
 *   curl "https://generativelanguage.googleapis.com/v1beta/models?key=$GEMINI_API_KEY"
 *
 * Model choice is not arbitrary. Given this prompt — a security-urgency email
 * naming a real company — the gemini-3.x flash models frequently swap the real
 * domain for "example.com", which ruins the one thing the feature is selling
 * (a genuinely personalised email). gemini-2.5-flash keeps the real domain
 * every time it was tested. Re-check that behaviour before changing this.
 */
export const GEMINI_MODEL = "gemini-2.5-flash";

/** Placeholder domains a model may substitute for the real company. */
const PLACEHOLDER_DOMAINS = [
  "example.com",
  "example.org",
  "yourcompany.com",
  "acme.com",
  "company.com",
];

/**
 * Last line of defence for the generated email: if the model swapped the real
 * company for a placeholder domain, put the real one back. This only ever
 * substitutes a value the code already knows — it does not add or alter any
 * claim, and every figure in the email is still computed in code upstream.
 */
export function restoreCompanyDomain(
  emailText: string,
  companyDomain: string
): string {
  if (emailText.includes(companyDomain)) return emailText;

  let corrected = emailText;
  for (const placeholder of PLACEHOLDER_DOMAINS) {
    corrected = corrected.replaceAll(placeholder, companyDomain);
  }
  return corrected;
}
