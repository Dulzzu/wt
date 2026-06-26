import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

function verifyToken(token, secret) {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expected = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  if (sig !== expected) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!payload.exp || payload.exp < Date.now()) return null;
  return payload;
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export default async (req) => {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const secret = process.env.AUTH_SECRET || "change-me-insecure-default";
  const payload = verifyToken(token, secret);
  if (!payload || !payload.email) return json({ error: "unauthorized" }, 401);

  const users = getStore("wt-users");
  const user = await users.get(`user:${payload.email}`, { type: "json" });
  if (!user) return json({ error: "not_found" }, 404);

  return json({ user: { email: user.email, subscriptionActive: user.subscriptionActive } }, 200);
};

export const config = { path: "/api/me", method: "GET" };
