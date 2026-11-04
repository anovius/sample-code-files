// =============================================================================
// Edge Function: shopify-lead-intake
//
// Receives Shopify "orders/create" webhooks, turns each order into a lead and
// routes it to a rep with public.route_lead().
//
//   1. Reject anything that is not a POST, too large, or not signed by Shopify
//   2. Ignore other webhook topics and orders without a usable postal code
//   3. Insert the lead; a retried webhook hits the unique (source, external_ref)
//      key and reuses the existing lead instead of creating a duplicate
//   4. Route it; route_lead is idempotent, so retries never double-assign
//
// Shopify retries any non-2xx response, so we only return an error when a retry
// can actually succeed (database or network failure). Bad input gets a 2xx
// "ignored" answer and a log line instead of an endless retry loop.
//
// Secrets: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by the
// platform. SHOPIFY_WEBHOOK_SECRET is set with `supabase secrets set`.
// Deploy with --no-verify-jwt: Shopify signs with HMAC, not a Supabase JWT.
// =============================================================================

import { createClient } from "jsr:@supabase/supabase-js@2";

const MAX_BODY_BYTES = 512 * 1024;
const HANDLED_TOPIC = "orders/create";
const UNIQUE_VIOLATION = "23505";

// same rules as the CHECK constraints on public.leads
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PHONE_RE = /^\+?[0-9 ()-]{7,20}$/;
const ZIP_RE = /^(\d{5})(?:-\d{4})?$/;

interface ShopifyAddress {
  first_name?: string | null;
  last_name?: string | null;
  phone?: string | null;
  zip?: string | null;
}

interface ShopifyOrder {
  id: number;
  email?: string | null;
  phone?: string | null;
  customer?: {
    first_name?: string | null;
    last_name?: string | null;
    email?: string | null;
    phone?: string | null;
  } | null;
  shipping_address?: ShopifyAddress | null;
  billing_address?: ShopifyAddress | null;
}

interface LeadInsert {
  source: "shopify";
  external_ref: string;
  full_name: string;
  email: string | null;
  phone: string | null;
  postal_code: string;
}

type ParseResult =
  | { ok: true; lead: LeadInsert }
  | { ok: false; reason: string };

const secret = Deno.env.get("SHOPIFY_WEBHOOK_SECRET");
const supabaseUrl = Deno.env.get("SUPABASE_URL");
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

if (!secret || !supabaseUrl || !serviceRoleKey) {
  throw new Error("Missing SHOPIFY_WEBHOOK_SECRET, SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
}

const supabase = createClient(supabaseUrl, serviceRoleKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// HMAC key is imported once per isolate, not per request
const hmacKey = crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(secret),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["verify"],
);

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function decodeBase64(value: string): ArrayBuffer | null {
  try {
    return Uint8Array.from(atob(value), (c) => c.charCodeAt(0)).buffer as ArrayBuffer;
  } catch {
    return null;
  }
}

// crypto.subtle.verify compares in constant time, so no timing side channel
async function isSignedByShopify(raw: ArrayBuffer, header: string | null): Promise<boolean> {
  if (!header) return false;
  const signature = decodeBase64(header.trim());
  if (!signature || signature.byteLength !== 32) return false;
  return await crypto.subtle.verify("HMAC", await hmacKey, signature, raw);
}

function clean(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function parseOrder(order: ShopifyOrder): ParseResult {
  if (!Number.isSafeInteger(order?.id) || order.id <= 0) {
    return { ok: false, reason: "missing_order_id" };
  }

  const address = order.shipping_address ?? order.billing_address ?? null;

  const zipMatch = clean(address?.zip)?.match(ZIP_RE);
  if (!zipMatch) return { ok: false, reason: "invalid_postal_code" };

  const fullName = [
    clean(order.customer?.first_name) ?? clean(address?.first_name),
    clean(order.customer?.last_name) ?? clean(address?.last_name),
  ].filter(Boolean).join(" ");
  if (!fullName) return { ok: false, reason: "missing_name" };

  const email = clean(order.email ?? order.customer?.email)?.toLowerCase() ?? null;
  const phone = clean(order.phone ?? order.customer?.phone ?? address?.phone);

  return {
    ok: true,
    lead: {
      source: "shopify",
      external_ref: String(order.id),
      full_name: fullName,
      // a malformed contact detail should not cost us the lead
      email: email && EMAIL_RE.test(email) ? email : null,
      phone: phone && PHONE_RE.test(phone) ? phone : null,
      postal_code: zipMatch[1],
    },
  };
}

async function insertOrFindLead(lead: LeadInsert): Promise<string> {
  const inserted = await supabase.from("leads").insert(lead).select("id").single();
  if (!inserted.error) return inserted.data.id as string;

  if (inserted.error.code !== UNIQUE_VIOLATION) throw inserted.error;

  // webhook retry: the lead already exists
  const existing = await supabase
    .from("leads")
    .select("id")
    .eq("source", lead.source)
    .eq("external_ref", lead.external_ref)
    .single();
  if (existing.error) throw existing.error;
  return existing.data.id as string;
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method !== "POST") {
    return json(405, { error: "method_not_allowed" });
  }

  const declaredLength = Number(req.headers.get("content-length") ?? "0");
  if (declaredLength > MAX_BODY_BYTES) {
    return json(413, { error: "payload_too_large" });
  }

  const raw = await req.arrayBuffer();
  if (raw.byteLength > MAX_BODY_BYTES) {
    return json(413, { error: "payload_too_large" });
  }

  if (!(await isSignedByShopify(raw, req.headers.get("x-shopify-hmac-sha256")))) {
    return json(401, { error: "invalid_signature" });
  }

  const topic = req.headers.get("x-shopify-topic");
  if (topic !== HANDLED_TOPIC) {
    return json(200, { status: "ignored", reason: "unhandled_topic" });
  }

  let order: ShopifyOrder;
  try {
    order = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return json(400, { error: "invalid_json" });
  }

  const parsed = parseOrder(order);
  if (!parsed.ok) {
    console.warn(JSON.stringify({ msg: "order ignored", reason: parsed.reason, order_id: order?.id ?? null }));
    return json(200, { status: "ignored", reason: parsed.reason });
  }

  try {
    const leadId = await insertOrFindLead(parsed.lead);

    const routed = await supabase.rpc("route_lead", { p_lead_id: leadId });
    if (routed.error) throw routed.error;

    const repId = (routed.data as string | null) ?? null;
    return json(200, {
      status: repId ? "routed" : "unassigned",
      lead_id: leadId,
      rep_id: repId,
    });
  } catch (error) {
    // 5xx makes Shopify retry; insert and routing are both safe to repeat
    console.error(JSON.stringify({
      msg: "lead intake failed",
      order_id: parsed.lead.external_ref,
      error: error instanceof Error ? error.message : (error as { message?: string })?.message ?? String(error),
    }));
    return json(500, { error: "intake_failed" });
  }
});
