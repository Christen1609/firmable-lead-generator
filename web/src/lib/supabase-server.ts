import "server-only";
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const serviceKey = process.env.SUPABASE_SERVICE_KEY!;

/**
 * Full-access client. The service key bypasses RLS, so this can read and write
 * anything. The server-only import above turns any client-side import of this
 * file into a build error, which is the whole reason it lives apart from
 * supabase-public.ts.
 */
export const supabaseServer = createClient(supabaseUrl, serviceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});
