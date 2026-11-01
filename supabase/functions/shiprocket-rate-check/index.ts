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
  if (!ALLOWED_ORIGINS.has(origin)) return json({ ok: false, message: "Origin not allowed." }, 403, origin);
  if (req.method === "OPTIONS") return new Response("ok", { headers: {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  }});
  if (req.method !== "POST") return json({ ok: false, message: "Method not allowed." }, 405, origin);

  const authorization = req.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) return json({ ok: false, message: "Please sign in as the store administrator." }, 401, origin);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  let publishableKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  const keysRaw = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  if (keysRaw) {
    try { publishableKey = JSON.parse(keysRaw).default ?? publishableKey; }
    catch { return json({ ok: false, message: "Supabase publishable-key configuration is invalid." }, 500, origin); }
  }
  if (!supabaseUrl || !publishableKey) return json({ ok: false, message: "Supabase authentication configuration is unavailable." }, 500, origin);

  const authRes = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: { apikey: publishableKey, Authorization: authorization },
    signal: AbortSignal.timeout(10000),
  }).catch(() => null);
  if (!authRes?.ok) return json({ ok: false, message: "Your admin session is invalid or expired. Please sign in again." }, 401, origin);
  const user = await authRes.json();
  if (user?.id !== ADMIN_USER_ID || (user?.email ?? "").toLowerCase() !== "admin@enga.in") {
    return json({ ok: false, message: "Only the authorised enga.in administrator can check courier rates." }, 403, origin);
  }

  let input: Record<string, unknown>;
  try { input = await req.json(); } catch { return json({ ok: false, message: "Invalid request body." }, 400, origin); }
  const pin = String(input.delivery_postcode ?? "").trim();
  const weight = Number(input.weight_kg);
  const length = Number(input.length_cm);
  const breadth = Number(input.breadth_cm);
  const height = Number(input.height_cm);
  const declaredValue = Number(input.declared_value);
  if (!/^\d{6}$/.test(pin)) return json({ ok: false, message: "Enter a valid 6-digit delivery PIN code." }, 400, origin);
  if (!Number.isFinite(weight) || weight <= 0 || weight > 50 ||
      !Number.isFinite(length) || length < 1 || length > 200 ||
      !Number.isFinite(breadth) || breadth < 1 || breadth > 200 ||
      !Number.isFinite(height) || height < 1 || height > 200 ||
      !Number.isFinite(declaredValue) || declaredValue < 1 || declaredValue > 1000000) {
    return json({ ok: false, message: "Parcel weight, dimensions or declared value are invalid." }, 400, origin);
  }

  const email = Deno.env.get("SHIPROCKET_EMAIL");
  const password = Deno.env.get("SHIPROCKET_PASSWORD");
  if (!email || !password) return json({ ok: false, message: "Shiprocket API credentials are missing from Supabase secrets." }, 503, origin);

  try {
    const login = await fetch("https://apiv2.shiprocket.in/v1/external/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ email, password }),
      signal: AbortSignal.timeout(15000),
    });
    const loginData = await login.json().catch(() => ({}));
    if (!login.ok || typeof loginData?.token !== "string" || !loginData.token) {
      return json({ ok: false, message: login.status === 401 || login.status === 403
        ? "Shiprocket rejected the API user credentials or permissions."
        : `Shiprocket authentication failed (HTTP ${login.status}).` }, 502, origin);
    }

    const params = new URLSearchParams({
      pickup_postcode: "796181",
      delivery_postcode: pin,
      cod: "0",
      weight: String(weight),
      length: String(Math.round(length)),
      breadth: String(Math.round(breadth)),
      height: String(Math.round(height)),
      declared_value: String(Math.round(declaredValue)),
    });
    const rateRes = await fetch(`https://apiv2.shiprocket.in/v1/external/courier/serviceability/?${params}`, {
      headers: { Authorization: `Bearer ${loginData.token}`, Accept: "application/json" },
      signal: AbortSignal.timeout(20000),
    });
    const rateData = await rateRes.json().catch(() => ({}));
    if (!rateRes.ok) return json({ ok: false, message: `Shiprocket rate check failed (HTTP ${rateRes.status}).` }, 502, origin);
    const companies = Array.isArray(rateData?.data?.available_courier_companies) ? rateData.data.available_courier_companies : [];
    const couriers = companies.map((c: Record<string, unknown>) => ({
      courierId: c.courier_company_id ?? null,
      name: c.courier_name ?? "Courier",
      rate: Number(c.rate ?? c.freight_charge ?? 0),
      freightCharge: Number(c.freight_charge ?? 0),
      rtoCharges: c.rto_charges == null ? null : Number(c.rto_charges),
      chargeWeight: Number(c.charge_weight ?? 0),
      etd: c.etd ?? c.estimated_delivery_days ?? null,
      rating: c.rating ?? null,
      pickupAvailability: c.pickup_availability ?? null,
      blocked: c.blocked === 1 || c.blocked === "1",
    })).filter((c: { rate: number; blocked: boolean }) => Number.isFinite(c.rate) && c.rate >= 0 && !c.blocked)
      .sort((a: { rate: number }, b: { rate: number }) => a.rate - b.rate);
    return json({
      ok: true,
      originPin: "796181",
      destinationPin: pin,
      actualWeightKg: weight,
      volumetricWeightKg: Number(((length * breadth * height) / 5000).toFixed(3)),
      couriers,
      message: couriers.length ? "Courier rates retrieved. No order or shipment was created." : "Shiprocket returned no available courier services for this route and parcel.",
    }, 200, origin);
  } catch (error) {
    return json({ ok: false, message: error instanceof Error && error.name === "TimeoutError"
      ? "Shiprocket took too long to respond. Please try again."
      : "Could not complete the Shiprocket rate check. Please try again." }, 502, origin);
  }
});
