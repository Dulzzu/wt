import { getStore } from "@netlify/blobs";

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export default async (req) => {
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad_request" }, 400);
  }

  const name = String(body.name || "").trim().slice(0, 80);
  const email = String(body.email || "").trim().slice(0, 120);
  const message = String(body.message || "").trim().slice(0, 2000);
  const lang = String(body.lang || "").trim().slice(0, 5);

  if (!name || !email || !message) {
    return json({ error: "fields_required" }, 400);
  }

  // ── basic anti-spam: max 5 messages per IP per hour ──
  const ip =
    req.headers.get("x-nf-client-connection-ip") ||
    req.headers.get("x-forwarded-for") ||
    "unknown";
  const rl = getStore("wt-ratelimit");
  const rlKey = `contact:${ip}`;
  const now = Date.now();
  let attempts = [];
  try {
    const raw = await rl.get(rlKey, { type: "json" });
    if (Array.isArray(raw)) attempts = raw.filter((t) => now - t < 3600_000);
  } catch {}
  if (attempts.length >= 5) return json({ error: "rate_limited" }, 429);

  const contacts = getStore("wt-contacts");
  const id = `msg_${now}_${Math.random().toString(36).slice(2, 8)}`;
  const entry = {
    id,
    name,
    email,
    message,
    lang,
    ip,
    read: false,
    createdAt: now,
  };
  await contacts.setJSON(`contact:${id}`, entry);

  attempts.push(now);
  await rl.setJSON(rlKey, attempts);

  return json({ ok: true, id }, 200);
};

export const config = { path: "/api/contact", method: "POST" };
