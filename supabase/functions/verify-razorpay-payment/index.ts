import "jsr:@supabase/functions-js/edge-runtime.d.ts";
const corsHeaders = {"Access-Control-Allow-Origin":"https://enga.in","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Vary":"Origin"};
function json(data: unknown,status=200){return new Response(JSON.stringify(data),{status,headers:{...corsHeaders,"Content-Type":"application/json"}});}
function env(name:string){const v=Deno.env.get(name);if(!v)throw new Error(`Missing server configuration: ${name}`);return v;}
function headers(key:string){return {"apikey":key,"Authorization":`Bearer ${key}`,"Content-Type":"application/json"};}
function hex(bytes:ArrayBuffer){return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");}
async function hmac(secret:string,message:string){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return hex(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(message)));}
function safeEqual(a:string,b:string){if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0;}
const originalHandler = async (req:Request)=>{
 if(req.method==="OPTIONS")return new Response("ok",{headers:corsHeaders});
 const origin=req.headers.get("origin");if(origin&&origin!=="https://enga.in"&&origin!=="https://www.enga.in"&&origin!=="https://shop.enga.in"&&!origin.endsWith(".github.io"))return json({error:"Origin not allowed"},403);
 if(req.method!=="POST")return json({error:"Method not allowed"},405);
 try{
  const raw=await req.text();if(raw.length>12000)return json({error:"Request too large"},413);
  const b=JSON.parse(raw),{orderId,razorpay_order_id:razorOrderId,razorpay_payment_id:paymentId,razorpay_signature:signature}=b;
  if(![orderId,razorOrderId,paymentId,signature].every(v=>typeof v==="string"&&v.length>0&&v.length<256))return json({error:"Payment verification details are incomplete"},400);
  const projectUrl=env("SUPABASE_URL"),serviceKey=env("SUPABASE_SERVICE_ROLE_KEY"),keyId=env("RAZORPAY_KEY_ID"),keySecret=env("RAZORPAY_KEY_SECRET");
  if(!safeEqual(await hmac(keySecret,`${razorOrderId}|${paymentId}`),signature))return json({error:"Payment signature could not be verified"},400);
  const auth=btoa(`${keyId}:${keySecret}`);
  const pr=await fetch(`https://api.razorpay.com/v1/payments/${encodeURIComponent(paymentId)}`,{headers:{"Authorization":`Basic ${auth}`}});
  const payment=await pr.json();
  if(!pr.ok||payment.order_id!==razorOrderId||payment.currency!=="INR"||payment.status!=="captured")return json({error:"Razorpay payment has not been captured or is invalid"},400);
  const url=`${projectUrl}/rest/v1/store_orders?id=eq.${encodeURIComponent(orderId)}&razorpay_order_id=eq.${encodeURIComponent(razorOrderId)}&select=id,order_number,total_inr,payment_status`;
  const or=await fetch(url,{headers:headers(serviceKey)});if(!or.ok)throw new Error("Could not retrieve order");
  const orders=await or.json();if(!Array.isArray(orders)||orders.length!==1)return json({error:"Order does not match this payment"},404);
  const order=orders[0];if(Number(payment.amount)!==Number(order.total_inr)*100)return json({error:"Payment amount does not match the order"},400);
  if(order.payment_status==="paid")return json({success:true,orderNumber:order.order_number,alreadyVerified:true});
  if(order.payment_status!=="pending")return json({error:"This order is no longer awaiting payment"},409);
  const finalized=await fetch(`${projectUrl}/rest/v1/rpc/finalize_store_order_payment`,{
   method:"POST",headers:headers(serviceKey),body:JSON.stringify({p_order_id:orderId,p_payment_id:paymentId})
  });
  if(!finalized.ok){console.error("finalize order failed",await finalized.text());throw new Error("Could not finalize paid order");}
  const result=await finalized.json(),row=Array.isArray(result)?result[0]:result;
  return json({success:true,orderNumber:row?.order_number||order.order_number,stockIssue:!!row?.stock_issue});
 }catch(e){console.error("verify-razorpay-payment:",e);return json({error:"Payment verification failed. If money was deducted, contact enga.in support with your order details."},500);}
};

Deno.serve(async (req: Request) => {
 const origin = req.headers.get("origin") ?? "";
 const allowed = !origin || origin === "https://enga.in" || origin === "https://www.enga.in" || origin === "https://shop.enga.in" || origin.endsWith(".github.io");
 if (!allowed) return new Response(JSON.stringify({error:"Origin not allowed"}), {status:403, headers:{"Content-Type":"application/json","Access-Control-Allow-Origin":"https://enga.in","Vary":"Origin"}});
 const response = await originalHandler(req);
 if (!origin) return response;
 const headers = new Headers(response.headers);
 headers.set("Access-Control-Allow-Origin", origin);
 headers.set("Vary", "Origin");
 return new Response(response.body, {status:response.status, statusText:response.statusText, headers});
});