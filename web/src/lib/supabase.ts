import { createClient } from "@supabase/supabase-js";

/**
 * Read-only Supabase client, safe to reach the browser.
 *
 * Uses the publishable (anon) key, which is subject to Row Level Security. The
 * policies in supabase/rls_policies.sql grant SELECT on Companies,
 * Company_Vulns and settings, and grant no write access at all — an insert or
 * update with this key fails on the policy check rather than being trusted.
 *
 * This previously held a service-role key under a NEXT_PUBLIC_ name. That key
 * bypasses RLS completely, so one client-side import of this module would have
 * inlined full database access into the browser bundle. Writes now live in
 * supabase-admin.ts, which cannot be imported from client code.
 */
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);
