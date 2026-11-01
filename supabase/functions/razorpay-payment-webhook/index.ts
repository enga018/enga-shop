import "jsr:@supabase/functions-js/edge-runtime.d.ts";

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function env(name: string) {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}

function apiHeaders(serviceKey: string) {
  return {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    "Content-Type": "application/json",
  };
}

function toHex(bytes: ArrayBuffer) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(secret: string, message: Uint8Array) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, message));
}

function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    // Keep the original bytes intact: Razorpay signs the raw HTTP request body.
    const rawBody = new Uint8Array(await req.arrayBuffer());
    if (!rawBody.length || rawBody.length > 1_000_000) {
      return json({ error: "Invalid webhook body" }, 400);
    }

    const signature = req.headers.get("x-razorpay-signature") ?? "";
    if (!/^[a-f0-9]{64}$/i.test(signature)) {
      return json({ error: "Missing or invalid webhook signature" }, 400);
    }

    const webhookSecret = env("RAZORPAY_WEBHOOK_SECRET");
    const expected = await hmacSha256(webhookSecret, rawBody);
    if (!safeEqual(expected.toLowerCase(), signature.toLowerCase())) {
      return json({ error: "Webhook signature verification failed" }, 400);
    }

    let event: any;
    try {
      event = JSON.parse(new TextDecoder().decode(rawBody));
    } catch {
      return json({ error: "Invalid JSON payload" }, 400);
    }

    // Only captured payments can confirm an order. Other events are acknowledged
    // without changing order or inventory state.
    if (event?.event !== "payment.captured") {
      return json({ received: true, ignored: true });
    }

    const payment = event?.payload?.payment?.entity;
    if (
      !payment ||
      typeof payment.id !== "string" ||
      !/^pay_[A-Za-z0-9]+$/.test(payment.id) ||
      typeof payment.order_id !== "string" ||
      !/^order_[A-Za-z0-9]+$/.test(payment.order_id) ||
      payment.status !== "captured" ||
      payment.captured !== true ||
      payment.currency !== "INR" ||
      !Number.isSafeInteger(payment.amount) ||
      payment.amount <= 0
    ) {
      return json({ error: "Captured payment details are invalid" }, 400);
    }

    const projectUrl = env("SUPABASE_URL");
    const serviceKey = env("SUPABASE_SERVICE_ROLE_KEY");
    const orderUrl = new URL(`${projectUrl}/rest/v1/store_orders`);
    orderUrl.searchParams.set(
      "select",
      "id,order_number,total_inr,payment_status,razorpay_payment_id",
    );
    orderUrl.searchParams.set("razorpay_order_id", `eq.${payment.order_id}`);

    const orderResponse = await fetch(orderUrl, { headers: apiHeaders(serviceKey) });
    if (!orderResponse.ok) {
      console.error("Webhook order lookup failed", orderResponse.status);
      throw new Error("Could not retrieve the matching store order");
    }

    const orders = await orderResponse.json();
    if (!Array.isArray(orders) || orders.length !== 1) {
      console.error("Captured payment has no matching store order", payment.order_id);
      return json({ received: true, ignored: true, reason: "order_not_found" });
    }

    const order = orders[0];
    if (payment.amount !== Number(order.total_inr) * 100) {
      console.error("Captured payment amount mismatch", order.order_number, payment.id);
      return json({ received: true, ignored: true, reason: "amount_mismatch" });
    }

    if (order.payment_status === "paid") {
      if (order.razorpay_payment_id === payment.id) {
        return json({ received: true, success: true, alreadyProcessed: true });
      }
      console.error("Additional captured payment for an already-paid order", order.order_number, payment.id);
      return json({ received: true, ignored: true, reason: "additional_payment_requires_review" });
    }

    if (order.payment_status !== "pending") {
      console.error("Captured payment belongs to a non-pending order", order.order_number, order.payment_status);
      return json({ received: true, ignored: true, reason: "order_not_pending" });
    }

    const finalizeResponse = await fetch(
      `${projectUrl}/rest/v1/rpc/finalize_store_order_payment`,
      {
        method: "POST",
        headers: apiHeaders(serviceKey),
        body: JSON.stringify({
          p_order_id: order.id,
          p_payment_id: payment.id,
        }),
      },
    );

    if (!finalizeResponse.ok) {
      console.error("Webhook order finalization failed", await finalizeResponse.text());
      throw new Error("Could not finalize the captured payment");
    }

    const finalized = await finalizeResponse.json();
    const result = Array.isArray(finalized) ? finalized[0] : finalized;

    // Re-read after the row-locked RPC to detect a concurrent second payment.
    const confirmUrl = new URL(`${projectUrl}/rest/v1/store_orders`);
    confirmUrl.searchParams.set("select", "razorpay_payment_id,payment_status");
    confirmUrl.searchParams.set("id", `eq.${order.id}`);
    const confirmResponse = await fetch(confirmUrl, { headers: apiHeaders(serviceKey) });
    if (!confirmResponse.ok) throw new Error("Could not confirm finalized payment state");
    const [confirmed] = await confirmResponse.json();
    if (
      confirmed?.payment_status !== "paid" ||
      confirmed?.razorpay_payment_id !== payment.id
    ) {
      console.error("Additional captured payment requires manual review", order.order_number, payment.id);
      return json({ received: true, ignored: true, reason: "additional_payment_requires_review" });
    }

    return json({
      received: true,
      success: true,
      orderNumber: result?.order_number ?? order.order_number,
      stockIssue: Boolean(result?.stock_issue),
    });
  } catch (error) {
    console.error("razorpay-payment-webhook:", error);
    return json({ error: "Webhook processing failed" }, 500);
  }
});
