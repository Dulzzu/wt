import crypto from "node:crypto";

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
function timingSafeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
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

  const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
  const secret = process.env.AUTH_SECRET || "change-me-insecure-default";

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    return json({ error: "admin_not_configured" }, 500);
  }
  const emailOk = email === ADMIN_EMAIL;
  const passOk = timingSafeEqual(password, ADMIN_PASSWORD);
  if (!emailOk || !passOk) return json({ error: "invalid_credentials" }, 401);

  const token = signToken({ admin: true, exp: Date.now() + 12 * 3600 * 1000 }, secret);
  return json({ token }, 200);
};

export const config = { path: "/api/admin-login", method: "POST" };
