import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const ADMIN_USER_ID = "32a7666a-cd46-41c3-80d3-9402e3682c34";
const ALLOWED_ORIGINS = new Set(["https://enga.in", "https://www.enga.in", "https://shop.enga.in"]);

function json(body: unknown, status = 200, origin = "") {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin",
    },
  });
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin") ?? "";
  if (!ALLOWED_ORIGINS.has(origin)) {
    return json({ connected: false, message: "Origin not allowed." }, 403, origin);
  }
  if (req.method === "OPTIONS") return new Response("ok", {
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin",
    },
  });
  if (req.method !== "POST") return json({ connected: false, message: "Method not allowed." }, 405, origin);

  const authorization = req.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) {
    return json({ connected: false, message: "Please sign in as the store administrator." }, 401, origin);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  let publishableKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  const publishableKeysRaw = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  if (publishableKeysRaw) {
    try {
      const keys = JSON.parse(publishableKeysRaw);
      publishableKey = keys.default ?? publishableKey;
    } catch {
      return json({ connected: false, message: "Supabase publishable-key configuration is invalid." }, 500, origin);
    }
  }
  if (!supabaseUrl || !publishableKey) {
    return json({ connected: false, message: "Supabase authentication configuration is unavailable." }, 500, origin);
  }

  // Validate the caller's actual Supabase Auth session. The gateway JWT check is
  // disabled for compatibility with the project's new publishable-key setup.
  const userResponse = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: { apikey: publishableKey, Authorization: authorization },
  });
  if (!userResponse.ok) {
    return json({ connected: false, message: "Your admin session is invalid or expired. Please sign in again." }, 401, origin);
  }
  const user = await userResponse.json();
  if (user?.id !== ADMIN_USER_ID || (user?.email ?? "").toLowerCase() !== "admin@enga.in") {
    return json({ connected: false, message: "Only the authorised enga.in administrator can test this connection." }, 403, origin);
  }

  const email = Deno.env.get("SHIPROCKET_EMAIL");
  const password = Deno.env.get("SHIPROCKET_PASSWORD");
  if (!email || !password) {
    return json({ connected: false, message: "Shiprocket API credentials are missing from Supabase Edge Function Secrets." }, 503, origin);
  }

  let shiprocketResponse: Response;
  try {
    shiprocketResponse = await fetch("https://apiv2.shiprocket.in/v1/external/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ email, password }),
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    return json({ connected: false, message: "Could not reach Shiprocket. Please try again." }, 502, origin);
  }

  const result = await shiprocketResponse.json().catch(() => ({}));
  if (!shiprocketResponse.ok || typeof result?.token !== "string" || !result.token) {
    const message = shiprocketResponse.status === 401 || shiprocketResponse.status === 403
      ? "Shiprocket rejected the API user credentials or permissions. Check the API user and buyer-details access settings."
      : shiprocketResponse.status === 429
      ? "Shiprocket rate-limited the login request. Wait a little and try again."
      : `Shiprocket authentication failed (HTTP ${shiprocketResponse.status}).`;
    return json({ connected: false, message }, 200, origin);
  }

  // Deliberately never return or persist the bearer token in this test endpoint.
  return json({
    connected: true,
    accountEmail: typeof result.email === "string" ? result.email : email,
    accountName: [result.first_name, result.last_name].filter((v) => typeof v === "string" && v).join(" ") || null,
    message: "Shiprocket API authentication succeeded. No shipment was created.",
  }, 200, origin);
});
