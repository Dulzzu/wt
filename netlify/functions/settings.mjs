import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const DEFAULTS = {
  discountEnabled: true,
  discountPercent: 75,
  basePrice: 340,
  fundedMin: 5000,
  fundedMax: 10000,
};

function verifyAdmin(req, secret) {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const [body, sig] = token.split(".");
  if (!body || !sig) return false;
  const expected = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  if (sig !== expected) return false;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return false;
  }
  return !!(payload.admin && payload.exp > Date.now());
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
function clampNum(n, min, max, fallback) {
  const v = Number(n);
  if (!Number.isFinite(v)) return fallback;
  return Math.min(max, Math.max(min, v));
}

export default async (req) => {
  const store = getStore("wt-settings");

  if (req.method === "GET") {
    let saved = null;
    try {
      saved = await store.get("config", { type: "json" });
    } catch {}
    return json({ ...DEFAULTS, ...(saved || {}) }, 200);
  }

  if (req.method === "POST") {
    const secret = process.env.AUTH_SECRET || "change-me-insecure-default";
    if (!verifyAdmin(req, secret)) return json({ error: "unauthorized" }, 401);

    let body;
    try {
      body = await req.json();
    } catch {
      return json({ error: "bad_request" }, 400);
    }

    let current = null;
    try {
      current = await store.get("config", { type: "json" });
    } catch {}
    current = { ...DEFAULTS, ...(current || {}) };

    const updated = {
      discountEnabled: typeof body.discountEnabled === "boolean" ? body.discountEnabled : current.discountEnabled,
      discountPercent: clampNum(body.discountPercent, 0, 95, current.discountPercent),
      basePrice: clampNum(body.basePrice, 1, 100000, current.basePrice),
      fundedMin: clampNum(body.fundedMin, 0, 10000000, current.fundedMin),
      fundedMax: clampNum(body.fundedMax, 0, 10000000, current.fundedMax),
    };
    if (updated.fundedMax < updated.fundedMin) {
      const tmp = updated.fundedMax;
      updated.fundedMax = updated.fundedMin;
      updated.fundedMin = tmp;
    }

    await store.setJSON("config", updated);
    return json({ ok: true, settings: updated }, 200);
  }

  return json({ error: "method_not_allowed" }, 405);
};

export const config = { path: "/api/settings" };
