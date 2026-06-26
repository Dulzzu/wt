import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

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

export default async (req) => {
  const secret = process.env.AUTH_SECRET || "change-me-insecure-default";
  if (!verifyAdmin(req, secret)) return json({ error: "unauthorized" }, 401);

  const users = getStore("wt-users");

  if (req.method === "GET") {
    const { blobs } = await users.list({ prefix: "user:" });
    const all = await Promise.all(blobs.map((b) => users.get(b.key, { type: "json" })));
    const safe = all
      .filter(Boolean)
      .map((u) => ({
        id: u.id,
        email: u.email,
        dob: u.dob,
        country: u.country,
        city: u.city,
        phone: u.phone,
        subscriptionActive: u.subscriptionActive,
        createdAt: u.createdAt,
      }))
      .sort((a, b) => b.createdAt - a.createdAt);
    return json({ users: safe }, 200);
  }

  if (req.method === "POST") {
    let body;
    try {
      body = await req.json();
    } catch {
      return json({ error: "bad_request" }, 400);
    }
    const email = String(body.email || "").trim().toLowerCase();
    if (!email) return json({ error: "email_required" }, 400);
    const user = await users.get(`user:${email}`, { type: "json" });
    if (!user) return json({ error: "not_found" }, 404);
    user.subscriptionActive = !user.subscriptionActive;
    await users.setJSON(`user:${email}`, user);
    return json({ subscriptionActive: user.subscriptionActive }, 200);
  }

  return json({ error: "method_not_allowed" }, 405);
};

export const config = { path: "/api/admin-users" };
