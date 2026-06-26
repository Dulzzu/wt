import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

function hashPassword(pw) {
  return crypto.createHash("sha256").update(pw).digest("hex");
}
function signToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}
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

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!email || !password) return json({ error: "fields_required" }, 400);

  const users = getStore("wt-users");
  const user = await users.get(`user:${email}`, { type: "json" });
  if (!user) return json({ error: "invalid_credentials" }, 401);
  if (hashPassword(password) !== user.passHash) {
    return json({ error: "invalid_credentials" }, 401);
  }

  const secret = process.env.AUTH_SECRET || "change-me-insecure-default";
  const token = signToken({ email, exp: Date.now() + 30 * 24 * 3600 * 1000 }, secret);

  return json(
    { token, user: { email: user.email, subscriptionActive: user.subscriptionActive } },
    200
  );
};

export const config = { path: "/api/login", method: "POST" };
