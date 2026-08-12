import "server-only";
import { createClient } from "@supabase/supabase-js";

/**
 * Write client for server-side code only.
 *
 * Uses the service-role key, which bypasses Row Level Security — the pipeline
 * needs to upsert into Companies and Company_Vulns, and the read policies
 * deliberately grant no write access to anon.
 *
 * The `server-only` import is the guard: if any client component ever pulls
 * this module in, the build fails with an explicit error rather than quietly
 * shipping a full-access database key to the browser. That failure mode is the
 * entire reason this file is separate from supabase.ts.
 *
 * SUPABASE_SERVICE_KEY has no NEXT_PUBLIC_ prefix, so Next will not inline it
 * into client bundles even by accident.
 */
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const serviceKey = process.env.SUPABASE_SERVICE_KEY!;

export const supabaseAdmin = createClient(supabaseUrl, serviceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});
