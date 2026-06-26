import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

function hashPassword(pw) {
  return crypto.createHash("sha256").update(pw).digest("hex");
}
function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}
function isValidPhone(p) {
  return /^[+]?[0-9\s\-]{7,15}$/.test(p);
}
function calcAge(dobStr) {
  const dob = new Date(dobStr);
  if (isNaN(dob.getTime())) return -1;
  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
  return age;
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
  const dob = String(body.dob || "");
  const country = String(body.country || "").trim().slice(0, 100);
  const city = String(body.city || "").trim().slice(0, 100);
  const phone = String(body.phone || "").trim().slice(0, 30);

  if (!email || !password || !dob || !country || !city || !phone) {
    return json({ error: "fields_required" }, 400);
  }
  if (!isValidEmail(email)) return json({ error: "invalid_email" }, 400);
  if (password.length < 6) return json({ error: "password_short" }, 400);
  if (!isValidPhone(phone)) return json({ error: "invalid_phone" }, 400);
  if (calcAge(dob) < 18) return json({ error: "underage" }, 400);

  // ── basic anti-bot: max 5 registrations per IP per hour ──
  const ip =
    req.headers.get("x-nf-client-connection-ip") ||
    req.headers.get("x-forwarded-for") ||
    "unknown";
  const rl = getStore("wt-ratelimit");
  const rlKey = `register:${ip}`;
  const now = Date.now();
  let attempts = [];
  try {
    const raw = await rl.get(rlKey, { type: "json" });
    if (Array.isArray(raw)) attempts = raw.filter((t) => now - t < 3600_000);
  } catch {}
  if (attempts.length >= 5) return json({ error: "rate_limited" }, 429);

  const users = getStore("wt-users");
  const existing = await users.get(`user:${email}`, { type: "json" });
  if (existing) return json({ error: "email_exists" }, 409);

  const user = {
    id: `u_${now}_${Math.random().toString(36).slice(2, 8)}`,
    email,
    passHash: hashPassword(password),
    dob,
    country,
    city,
    phone,
    subscriptionActive: false,
    createdAt: now,
  };
  await users.setJSON(`user:${email}`, user);

  attempts.push(now);
  await rl.setJSON(rlKey, attempts);

  const secret = process.env.AUTH_SECRET || "change-me-insecure-default";
  const token = signToken({ email, exp: now + 30 * 24 * 3600 * 1000 }, secret);

  return json(
    { token, user: { email: user.email, subscriptionActive: user.subscriptionActive } },
    200
  );
};

export const config = { path: "/api/register", method: "POST" };
