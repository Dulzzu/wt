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

  const contacts = getStore("wt-contacts");

  if (req.method === "GET") {
    const { blobs } = await contacts.list({ prefix: "contact:" });
    const all = await Promise.all(blobs.map((b) => contacts.get(b.key, { type: "json" })));
    const safe = all.filter(Boolean).sort((a, b) => b.createdAt - a.createdAt);
    return json({ messages: safe }, 200);
  }

  if (req.method === "POST") {
    // mark as read / unread, or delete
    let body;
    try {
      body = await req.json();
    } catch {
      return json({ error: "bad_request" }, 400);
    }
    const id = String(body.id || "");
    if (!id) return json({ error: "id_required" }, 400);
    const key = `contact:${id}`;
    const entry = await contacts.get(key, { type: "json" });
    if (!entry) return json({ error: "not_found" }, 404);

    if (body.action === "delete") {
      await contacts.delete(key);
      return json({ deleted: true }, 200);
    }

    entry.read = !entry.read;
    await contacts.setJSON(key, entry);
    return json({ read: entry.read }, 200);
  }

  return json({ error: "method_not_allowed" }, 405);
};

export const config = { path: "/api/admin-contacts" };
