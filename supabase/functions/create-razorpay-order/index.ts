import "jsr:@supabase/functions-js/edge-runtime.d.ts";
const corsHeaders={"Access-Control-Allow-Origin":"https://enga.in","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Vary":"Origin"};
function json(data:unknown,status=200){return new Response(JSON.stringify(data),{status,headers:{...corsHeaders,"Content-Type":"application/json"}});}
function env(name:string){const v=Deno.env.get(name);if(!v)throw new Error(`Missing server configuration: ${name}`);return v;}
function validText(v:unknown,max:number){return typeof v==="string"&&v.trim().length>0&&v.trim().length<=max;}
function headers(key:string){return {"apikey":key,"Authorization":`Bearer ${key}`,"Content-Type":"application/json"};}
async function sha256(s:string){const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,"0")).join("");}
const originalHandler = async (req:Request)=>{
 if(req.method==="OPTIONS")return new Response("ok",{headers:corsHeaders});
 const origin=req.headers.get("origin");if(origin&&origin!=="https://enga.in"&&origin!=="https://www.enga.in"&&origin!=="https://shop.enga.in"&&!origin.endsWith(".github.io"))return json({error:"Origin not allowed"},403);
 if(req.method!=="POST")return json({error:"Method not allowed"},405);
 try{
  const raw=await req.text();if(raw.length>20000)return json({error:"Request too large"},413);
  const body=JSON.parse(raw),customer=body.customer??{};
  const required=["name","mobile","email","addressLine","locality","town","district","state","pincode"];
  for(const k of required)if(!validText(customer[k],k==="addressLine"?180:k==="email"?254:100))return json({error:`Please enter a valid ${k}`},400);
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customer.email.trim()))return json({error:"Please enter a valid email address"},400);
  if(!/^[6-9][0-9]{9}$/.test(customer.mobile.replace(/\D/g,"")))return json({error:"Please enter a valid 10-digit mobile number"},400);
  if(!/^[1-9][0-9]{5}$/.test(customer.pincode.trim()))return json({error:"Please enter a valid 6-digit PIN code"},400);
  if(!Array.isArray(body.items)||body.items.length<1||body.items.length>30)return json({error:"Your cart is empty or contains too many products"},400);
  const requested=new Map<string,number>();
  for(const item of body.items){
   if(!item||typeof item.id!=="string"||!/^[0-9a-f-]{36}$/i.test(item.id)||!Number.isInteger(item.qty)||item.qty<1||item.qty>20)return json({error:"Invalid cart item"},400);
   requested.set(item.id,(requested.get(item.id)??0)+item.qty);
  }
  if([...requested.values()].some(q=>q>20))return json({error:"Maximum quantity per product is 20"},400);
  const projectUrl=env("SUPABASE_URL"),serviceKey=env("SUPABASE_SERVICE_ROLE_KEY"),keyId=env("RAZORPAY_KEY_ID"),keySecret=env("RAZORPAY_KEY_SECRET");
  const ip=req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")?.split(",")[0].trim()||"unknown";
  const limit=await fetch(`${projectUrl}/rest/v1/rpc/consume_store_checkout_attempt`,{method:"POST",headers:headers(serviceKey),body:JSON.stringify({p_ip_hash:await sha256(ip+":"+serviceKey)})});
  if(!limit.ok)throw new Error("Checkout security check failed");
  if(await limit.json()!==true)return json({error:"Too many checkout attempts. Please wait and try again."},429);
  const ids=[...requested.keys()],query=new URLSearchParams({select:"id,name,price_inr,inventory_status,inventory_quantity,status,image_paths",id:`in.(${ids.join(",")})`,status:"eq.published"});
  const productResponse=await fetch(`${projectUrl}/rest/v1/store_products?${query}`,{headers:headers(serviceKey)});
  if(!productResponse.ok)throw new Error("Could not validate products");
  const found=await productResponse.json();
  if(!Array.isArray(found)||found.length!==ids.length)return json({error:"One or more products are no longer available. Please refresh your cart."},409);
  let subtotal=0;const orderItems=[];
  for(const id of ids){
   const product=found.find((p:any)=>p.id===id),qty=requested.get(id)!;
   if(product.inventory_status==="out_of_stock")return json({error:`${product.name} is out of stock`},409);
   if(product.inventory_status==="in_stock"&&Number(product.inventory_quantity)<qty)return json({error:`Only ${product.inventory_quantity} unit(s) of ${product.name} are available`},409);
   const unit=Math.round(Number(product.price_inr));if(!Number.isFinite(unit)||unit<=0)return json({error:`${product.name} has an invalid price`},409);
   const line=unit*qty;subtotal+=line;
   orderItems.push({product_id:product.id,product_name:product.name,unit_price_inr:unit,quantity:qty,line_total_inr:line,image_path:Array.isArray(product.image_paths)?product.image_paths[0]??null:null});
  }
  const shipping=subtotal>=999?0:99,total=subtotal+shipping;
  if(!Number.isSafeInteger(total)||total<=0||total>100000000)return json({error:"Order total is invalid"},400);
  const payload={customer_name:customer.name.trim(),customer_mobile:customer.mobile.replace(/\D/g,""),customer_email:customer.email.trim().toLowerCase(),address_line:customer.addressLine.trim(),locality:customer.locality.trim(),town:customer.town.trim(),district:customer.district.trim(),state:customer.state.trim(),pincode:customer.pincode.trim(),subtotal_inr:subtotal,shipping_fee_inr:shipping,total_inr:total};
  const created=await fetch(`${projectUrl}/rest/v1/store_orders?select=id,order_number`,{method:"POST",headers:{...headers(serviceKey),"Prefer":"return=representation"},body:JSON.stringify(payload)});
  if(!created.ok)throw new Error("Could not create order record");
  const [order]=await created.json();
  const items=await fetch(`${projectUrl}/rest/v1/store_order_items`,{method:"POST",headers:{...headers(serviceKey),"Prefer":"return=minimal"},body:JSON.stringify(orderItems.map(item=>({...item,order_id:order.id})))});
  if(!items.ok){await fetch(`${projectUrl}/rest/v1/store_orders?id=eq.${order.id}`,{method:"DELETE",headers:headers(serviceKey)});throw new Error("Could not save order items");}
  const auth=btoa(`${keyId}:${keySecret}`);
  const rr=await fetch("https://api.razorpay.com/v1/orders",{method:"POST",headers:{"Authorization":`Basic ${auth}`,"Content-Type":"application/json"},body:JSON.stringify({amount:total*100,currency:"INR",receipt:order.order_number,notes:{store_order_id:order.id,order_number:order.order_number}})});
  const razor=await rr.json();
  if(!rr.ok){await fetch(`${projectUrl}/rest/v1/store_orders?id=eq.${order.id}`,{method:"PATCH",headers:headers(serviceKey),body:JSON.stringify({payment_status:"failed",order_status:"cancelled"})});return json({error:"Razorpay could not create the payment order. Please try again."},502);}
  const linked=await fetch(`${projectUrl}/rest/v1/store_orders?id=eq.${order.id}`,{method:"PATCH",headers:{...headers(serviceKey),"Prefer":"return=minimal"},body:JSON.stringify({razorpay_order_id:razor.id})});
  if(!linked.ok)throw new Error("Could not link payment order");
  return json({orderId:order.id,orderNumber:order.order_number,razorpayOrderId:razor.id,amount:razor.amount,currency:razor.currency,keyId,subtotal,shipping,total});
 }catch(e){console.error("create-razorpay-order:",e);return json({error:e instanceof Error?e.message:"Unable to start checkout"},500);}
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