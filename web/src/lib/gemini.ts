
export const GEMINI_MODEL = "gemini-2.5-flash";


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
