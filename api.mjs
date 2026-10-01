import { createHash, pbkdf2, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const derive = promisify(pbkdf2);
const BUCKET = process.env.SUPABASE_AUDIO_BUCKET || "sukunh-audio";
const SB_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
// Prefer the current Supabase secret key; keep accepting the legacy service_role key.
const SB_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const ADMIN_PASSWORD = process.env.SUKUNH_ADMIN_PASSWORD || "";
const USER_TTL = 30 * 24 * 60 * 60;
const ADMIN_TTL = 8 * 60 * 60;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

function cookie(req, name) {
  const value = req.headers.get("cookie") || "";
  for (const part of value.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return "";
}

function cookieHeader(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function configured() { return Boolean(SB_URL && SB_KEY); }

async function supabase(path, options = {}) {
  if (!configured()) throw new Error("Connect the Supabase URL and service key in Netlify environment variables.");
  const response = await fetch(`${SB_URL}${path}`, {
    ...options,
    headers: {
      apikey: SB_KEY,
      // New sb_secret keys are API gateway keys, not JWTs; legacy service_role keys are JWTs.
      ...(SB_KEY.startsWith("sb_secret_") ? {} : { authorization: `Bearer ${SB_KEY}` }),
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...options.headers,
    },
  });
  const body = await response.text();
  const data = body ? (() => { try { return JSON.parse(body); } catch { return body; } })() : null;
  if (!response.ok) {
    const message = typeof data === "object" ? data?.message || data?.error_description || data?.error || data?.hint : data;
    throw new Error(message || `Supabase request failed (${response.status})`);
  }
  return { data, response };
}

async function db(table, query = "", options = {}) {
  return supabase(`/rest/v1/${table}${query ? `?${query}` : ""}`, options);
}

async function createSession(userId, role, seconds) {
  const token = randomBytes(36).toString("base64url");
  const expiresAt = new Date(Date.now() + seconds * 1000).toISOString();
  await db("app_sessions", "", {
    method: "POST",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({ token_hash: createHash("sha256").update(token).digest("hex"), user_id: userId, role, expires_at: expiresAt }),
  });
  return token;
}

async function session(req, role) {
  const token = cookie(req, role === "admin" ? "sukunh_admin" : "sukunh_user");
  if (!token) return null;
  const hash = createHash("sha256").update(token).digest("hex");
  const q = new URLSearchParams({ select: "token_hash,user_id,role,expires_at", token_hash: `eq.${hash}`, role: `eq.${role}`, limit: "1" });
  const { data } = await db("app_sessions", q.toString());
  const row = data?.[0];
  if (!row || new Date(row.expires_at).getTime() <= Date.now()) return null;
  return row;
}

async function deleteSession(req, role) {
  const token = cookie(req, role === "admin" ? "sukunh_admin" : "sukunh_user");
  if (!token) return;
  const hash = createHash("sha256").update(token).digest("hex");
  const q = new URLSearchParams({ token_hash: `eq.${hash}` });
  await db("app_sessions", q.toString(), { method: "DELETE", headers: { Prefer: "return=minimal" } });
}

async function isAdmin(req) { return Boolean(await session(req, "admin")); }
async function bodyJSON(req) {
  try { return await req.json(); } catch { throw new Error("Invalid request body."); }
}

function safeCompare(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

function audioPublicUrl(path) {
  return `${SB_URL}/storage/v1/object/public/${BUCKET}/${path.split("/").map(encodeURIComponent).join("/")}`;
}

function storagePath(url) {
  const prefix = `${SB_URL}/storage/v1/object/public/${BUCKET}/`;
  if (!url?.startsWith(prefix)) return "";
  return url.slice(prefix.length).split("/").map(decodeURIComponent).join("/");
}

async function uploadURL(req) {
  if (!(await isAdmin(req))) return json({ error: "Sign in as an administrator first." }, 401);
  const payload = await bodyJSON(req);
  const original = String(payload.filename || "");
  const ext = original.match(/\.[a-z0-9]{2,5}$/i)?.[0]?.toLowerCase() || "";
  if (![".mp3", ".m4a", ".ogg", ".wav", ".aac", ".mp4", ".webm"].includes(ext)) return json({ error: "Choose a supported audio file." }, 400);
  const size = Number(payload.size || 0);
  if (!size || size > 50 * 1024 * 1024) return json({ error: "Supabase Free allows files up to 50 MB each. This file is too large." }, 413);
  const path = `audio/${randomBytes(16).toString("hex")}${ext}`;
  const route = `/storage/v1/object/upload/sign/${encodeURIComponent(BUCKET)}/${path.split("/").map(encodeURIComponent).join("/")}`;
  const { data } = await supabase(route, { method: "POST", body: JSON.stringify({ expiresIn: 7200 }) });
  const signedPath = data?.url || data?.signedURL || data?.signedUrl;
  if (!signedPath) throw new Error("Supabase did not return an upload link.");
  const uploadUrl = signedPath.startsWith("http") ? signedPath : `${SB_URL}/storage/v1${signedPath.startsWith("/") ? signedPath : `/${signedPath}`}`;
  return json({ path, uploadUrl, audio_url: audioPublicUrl(path), token: data.token || "" });
}

async function routeRequest(req, route) {
  const method = req.method.toUpperCase();

  if (method === "GET" && route === "/health") return json({ ok: true, platform: "netlify", database: configured() ? "supabase" : "not-configured", adminConfigured: Boolean(ADMIN_PASSWORD), accountsEnabled: configured() });
  if (!configured()) return json({ error: "Supabase is not connected yet. Add its project URL and server key in Netlify settings." }, 503);

  if (method === "GET" && route === "/auth/me") {
    const auth = await session(req, "user");
    if (!auth) return json({ user: null });
    const q = new URLSearchParams({ select: "id,email,display_name,created_at", id: `eq.${auth.user_id}`, limit: "1" });
    const { data } = await db("app_users", q.toString());
    return json({ user: data?.[0] || null });
  }

  if (method === "GET" && ["/catalog", "/updates"].includes(route)) {
    const q = new URLSearchParams({ select: "id,kind,title,creator,series,language,description,audio_url,cover_url,duration,created_at", published: "eq.true", order: "created_at.desc" });
    const { data } = await db("media", q.toString());
    return json({ items: data || [], checkedAt: Math.floor(Date.now() / 1000) });
  }

  if (method === "GET" && route === "/admin/session") return json({ authenticated: await isAdmin(req), configured: Boolean(ADMIN_PASSWORD) });

  if (method === "GET" && route === "/admin/items") {
    if (!(await isAdmin(req))) return json({ error: "Sign in as an administrator first." }, 401);
    const { data } = await db("media", "select=*&order=created_at.desc");
    return json({ items: data || [] });
  }

  if (method === "POST" && ["/auth/register", "/auth/login"].includes(route)) {
    const payload = await bodyJSON(req);
    const email = String(payload.email || "").trim().toLowerCase();
    const password = String(payload.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json({ error: "Enter a valid email address." }, 400);
    let user;
    if (route.endsWith("register")) {
      const display_name = String(payload.name || "").trim();
      if (!display_name || display_name.length > 80) return json({ error: "Enter a name (up to 80 characters)." }, 400);
      if (password.length < 12) return json({ error: "Use a password with at least 12 characters." }, 400);
      const salt = randomBytes(16);
      const password_hash = (await derive(password, salt, 240000, 32, "sha256")).toString("hex");
      const id = randomBytes(16).toString("hex");
      try {
        const { data } = await db("app_users", "", { method: "POST", headers: { Prefer: "return=representation" }, body: JSON.stringify({ id, email, display_name, password_salt: salt.toString("hex"), password_hash }) });
        user = data?.[0];
      } catch (e) {
        if (/duplicate|unique/i.test(e.message)) return json({ error: "An account with that email already exists. Sign in instead." }, 409);
        throw e;
      }
    } else {
      const q = new URLSearchParams({ select: "id,email,display_name,created_at,password_salt,password_hash", email: `eq.${email}`, limit: "1" });
      const { data } = await db("app_users", q.toString());
      const saved = data?.[0];
      const candidate = saved ? (await derive(password, Buffer.from(saved.password_salt, "hex"), 240000, 32, "sha256")).toString("hex") : "";
      if (!saved || !safeCompare(candidate, saved.password_hash)) return json({ error: "Email or password was not accepted." }, 401);
      user = { id: saved.id, email: saved.email, display_name: saved.display_name, created_at: saved.created_at };
    }
    if (!user) throw new Error("Could not create the account.");
    const token = await createSession(user.id, "user", USER_TTL);
    delete user.password_hash; delete user.password_salt;
    return json({ user }, 200, { "set-cookie": cookieHeader("sukunh_user", token, USER_TTL) });
  }

  if (method === "POST" && route === "/auth/logout") {
    await deleteSession(req, "user");
    return json({}, 200, { "set-cookie": cookieHeader("sukunh_user", "", 0) });
  }

  if (method === "POST" && route === "/admin/login") {
    if (!ADMIN_PASSWORD) return json({ error: "Set SUKUNH_ADMIN_PASSWORD in Netlify environment variables." }, 503);
    const payload = await bodyJSON(req);
    if (!safeCompare(payload.password || "", ADMIN_PASSWORD)) return json({ error: "That password was not accepted." }, 401);
    const token = await createSession(null, "admin", ADMIN_TTL);
    return json({ authenticated: true }, 200, { "set-cookie": cookieHeader("sukunh_admin", token, ADMIN_TTL) });
  }

  if (method === "POST" && route === "/admin/logout") {
    await deleteSession(req, "admin");
    return json({}, 200, { "set-cookie": cookieHeader("sukunh_admin", "", 0) });
  }

  if (method === "POST" && route === "/admin/upload-url") return uploadURL(req);

  if (method === "POST" && route === "/admin/items") {
    if (!(await isAdmin(req))) return json({ error: "Sign in as an administrator first." }, 401);
    const payload = await bodyJSON(req);
    const kind = String(payload.kind || "");
    const title = String(payload.title || "").trim();
    const creator = String(payload.creator || "").trim();
    const audio = String(payload.audio_url || "").trim();
    if (!["anasheed", "podcast", "adhkar"].includes(kind) || !title || !creator || !audio) return json({ error: "Choose a content type and provide a title, creator, and audio file or URL." }, 400);
    const item = {
      id: randomBytes(16).toString("hex"), kind, title, creator,
      series: String(payload.series || ""), language: String(payload.language || "Arabic"),
      description: String(payload.description || ""), audio_url: audio,
      cover_url: String(payload.cover_url || ""), duration: String(payload.duration || ""),
      published: true, created_at: new Date().toISOString(),
    };
    const { data } = await db("media", "", { method: "POST", headers: { Prefer: "return=representation" }, body: JSON.stringify(item) });
    return json({ id: data?.[0]?.id || item.id, message: "Content added to the SUKUNH library." }, 201);
  }

  if (method === "DELETE" && route.startsWith("/admin/items/")) {
    if (!(await isAdmin(req))) return json({ error: "Sign in as an administrator first." }, 401);
    const id = decodeURIComponent(route.slice("/admin/items/".length));
    const q = new URLSearchParams({ select: "audio_url", id: `eq.${id}`, limit: "1" });
    const { data } = await db("media", q.toString());
    if (!data?.[0]) return json({ error: "Content not found." }, 404);
    const path = storagePath(data[0].audio_url);
    if (path) await supabase("/storage/v1/object/" + encodeURIComponent(BUCKET), { method: "DELETE", body: JSON.stringify({ prefixes: [path] }) });
    const del = new URLSearchParams({ id: `eq.${id}` });
    await db("media", del.toString(), { method: "DELETE", headers: { Prefer: "return=minimal" } });
    return json({ message: "Content removed." });
  }

  return json({ error: "Not found" }, 404);
}

export default async (request) => {
  try {
    const url = new URL(request.url);
    const route = url.searchParams.get("path") || url.pathname.replace(/^\/.netlify\/functions\/api/, "");
    return await routeRequest(request, route.startsWith("/") ? route : `/${route}`);
  } catch (error) {
    console.error("SUKUNH API error:", error);
    return json({ error: error.message || "The SUKUNH service could not complete this request." }, 500);
  }
};
