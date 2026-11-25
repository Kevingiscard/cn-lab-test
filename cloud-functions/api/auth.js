// Banc d'essai jetable : inscription / connexion / profil / déconnexion.
// Stockage Blob EdgeOne, mot de passe haché (scrypt), JWT HS256 en cookie HttpOnly.
import { getStore } from "@edgeone/pages-blob";
import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const b64 = (b) => Buffer.from(b).toString("base64url");
const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
const secret = () => process.env.JWT_SECRET || "";

function sign(payload) {
  const h = b64(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64(JSON.stringify(payload));
  const s = createHmac("sha256", secret()).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${s}`;
}
function verify(token) {
  const [h, p, s] = String(token || "").split(".");
  if (!h || !p || !s || !secret()) return null;
  const good = createHmac("sha256", secret()).update(`${h}.${p}`).digest("base64url");
  const a = Buffer.from(s), c = Buffer.from(good);
  if (a.length !== c.length || !timingSafeEqual(a, c)) return null;
  const payload = JSON.parse(Buffer.from(p, "base64url").toString());
  return payload.exp > Math.floor(Date.now() / 1000) ? payload : null;
}
const cookieOf = (req, name) => (req.headers.get("cookie") || "").split(/;\s*/).map((x) => x.split("=")).find(([k]) => k === name)?.[1];
const key = (email) => "u/" + createHash("sha256").update(email).digest("hex");

export async function onRequest({ request }) {
  const url = new URL(request.url);
  const action = url.searchParams.get("a") || "";
  const store = getStore({ name: "lab-users", consistency: "strong" });
  if (!secret()) return json({ error: "JWT_SECRET absent" }, 500);

  if (action === "register" && request.method === "POST") {
    const { email, password, role } = await request.json().catch(() => ({}));
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email || "") || (password || "").length < 10) return json({ error: "email ou mot de passe invalide (10 caractères min)" }, 400);
    const k = key(email.toLowerCase());
    if (await store.get(k)) return json({ error: "compte existant" }, 409);
    const salt = randomBytes(16);
    const hash = scryptSync(password, salt, 32);
    const user = { id: randomBytes(8).toString("hex"), email: email.toLowerCase(), role: "apprenant", salt: salt.toString("hex"), hash: hash.toString("hex"), createdAt: Date.now() };
    await store.set(k, JSON.stringify(user));
    return json({ ok: true, id: user.id, role: user.role }, 201);
  }
  if (action === "login" && request.method === "POST") {
    const { email, password } = await request.json().catch(() => ({}));
    const raw = await store.get(key(String(email || "").toLowerCase()));
    if (!raw) return json({ error: "identifiants invalides" }, 401);
    const u = JSON.parse(raw);
    const test = scryptSync(String(password || ""), Buffer.from(u.salt, "hex"), 32);
    if (!timingSafeEqual(test, Buffer.from(u.hash, "hex"))) return json({ error: "identifiants invalides" }, 401);
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = sign({ sub: u.id, role: u.role, exp });
    return json({ ok: true }, 200, { "Set-Cookie": `jwt_token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600` });
  }
  if (action === "me") {
    const p = verify(cookieOf(request, "jwt_token"));
    return p ? json({ id: p.sub, role: p.role }) : json({ error: "non authentifié" }, 401);
  }
  if (action === "logout" && request.method === "POST") {
    return json({ ok: true }, 200, { "Set-Cookie": "jwt_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" });
  }
  return json({ error: "action inconnue" }, 404);
}
