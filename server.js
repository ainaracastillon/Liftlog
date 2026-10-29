// Liftlog: servidor web + API. Datos en Postgres (Neon).
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL) {
  console.error("Falta la variable DATABASE_URL");
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
});
const q = (text, params) => pool.query(text, params);

/* ---------- contraseñas y sesiones ---------- */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}
function checkPassword(password, stored) {
  const [, salt, hash] = String(stored).split("$");
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(password, salt, 64);
  const real = Buffer.from(hash, "hex");
  return real.length === test.length && crypto.timingSafeEqual(real, test);
}
const SESSION_DAYS = 90;
const COOKIE = "liftlog_session";
function readCookie(req) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === COOKIE) return decodeURIComponent(v.join("="));
  }
  return null;
}
function setCookie(res, token, maxAgeSec) {
  const secure = process.env.NODE_ENV === "production" || process.env.RENDER ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${token ? encodeURIComponent(token) : ""}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${secure}`
  );
}
async function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await q("INSERT INTO sessions (token, user_id) VALUES ($1, $2)", [token, userId]);
  setCookie(res, token, SESSION_DAYS * 86400);
}
const publicUser = (u) => ({
  id: u.id,
  username: u.username,
  name: u.name,
  email: u.email,
  isAdmin: !!u.is_admin,
});

/* ---------- base de datos ---------- */
async function migrate() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username text UNIQUE NOT NULL,
    email text UNIQUE,
    name text NOT NULL,
    pass_hash text NOT NULL,
    is_admin boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz
  )`);
  await q(`CREATE TABLE IF NOT EXISTS sessions (
    token text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS docs (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key text NOT NULL,
    data jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
  )`);
  await q("DELETE FROM sessions WHERE created_at < now() - interval '90 days'");

  // Superadmin inicial, definido con variables de entorno (nunca en el código).
  const { ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_EMAIL, ADMIN_NAME } = process.env;
  if (ADMIN_USERNAME && ADMIN_PASSWORD) {
    const username = ADMIN_USERNAME.trim().toLowerCase();
    const email = ADMIN_EMAIL ? ADMIN_EMAIL.trim().toLowerCase() : null;
    const { rows } = await q("SELECT id FROM users WHERE username = $1", [username]);
    if (rows.length) {
      await q("UPDATE users SET is_admin = true, email = COALESCE(email, $2) WHERE id = $1", [rows[0].id, email]);
    } else {
      await q(
        "INSERT INTO users (username, email, name, pass_hash, is_admin) VALUES ($1, $2, $3, $4, true)",
        [username, email, ADMIN_NAME || username, hashPassword(ADMIN_PASSWORD)]
      );
      console.log(`Superadmin creado: ${username}`);
    }
  }
}

/* ---------- app ---------- */
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));

// Freno sencillo contra fuerza bruta en el login
const attempts = new Map();
function limited(req) {
  const key = req.ip;
  const now = Date.now();
  const list = (attempts.get(key) || []).filter((t) => now - t < 15 * 60 * 1000);
  list.push(now);
  attempts.set(key, list);
  return list.length > 20;
}

async function auth(req, res, next) {
  try {
    const token = readCookie(req);
    if (!token) return res.status(401).json({ error: "Inicia sesión" });
    const { rows } = await q(
      `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token = $1 AND s.created_at > now() - interval '90 days'`,
      [token]
    );
    if (!rows.length) return res.status(401).json({ error: "Tu sesión ha caducado. Vuelve a entrar." });
    req.user = rows[0];
    q("UPDATE users SET last_seen = now() WHERE id = $1", [req.user.id]).catch(() => {});
    next();
  } catch (e) {
    next(e);
  }
}
const admin = (req, res, next) =>
  req.user && req.user.is_admin ? next() : res.status(403).json({ error: "Solo para administradores" });

const USER_RE = /^[a-z0-9._-]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post("/api/register", async (req, res, next) => {
  try {
    if (limited(req)) return res.status(429).json({ error: "Demasiados intentos. Espera unos minutos." });
    const username = String(req.body.username || "").trim().toLowerCase();
    const name = String(req.body.name || "").trim().slice(0, 60);
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!USER_RE.test(username))
      return res.status(400).json({ error: "El usuario debe tener 3 a 30 letras, números, puntos o guiones." });
    if (!name) return res.status(400).json({ error: "Escribe tu nombre." });
    if (email && !EMAIL_RE.test(email)) return res.status(400).json({ error: "Ese email no parece válido." });
    if (password.length < 6) return res.status(400).json({ error: "La contraseña necesita al menos 6 caracteres." });
    const dup = await q("SELECT 1 FROM users WHERE username = $1 OR ($2 <> '' AND email = $2)", [username, email]);
    if (dup.rows.length) return res.status(409).json({ error: "Ese usuario o email ya está registrado." });
    const { rows } = await q(
      "INSERT INTO users (username, email, name, pass_hash) VALUES ($1, $2, $3, $4) RETURNING *",
      [username, email || null, name, hashPassword(password)]
    );
    await createSession(res, rows[0].id);
    res.json({ user: publicUser(rows[0]) });
  } catch (e) {
    next(e);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    if (limited(req)) return res.status(429).json({ error: "Demasiados intentos. Espera unos minutos." });
    const login = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const { rows } = await q("SELECT * FROM users WHERE username = $1 OR email = $1", [login]);
    if (!rows.length || !checkPassword(password, rows[0].pass_hash))
      return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
    await createSession(res, rows[0].id);
    res.json({ user: publicUser(rows[0]) });
  } catch (e) {
    next(e);
  }
});

app.post("/api/logout", async (req, res) => {
  const token = readCookie(req);
  if (token) await q("DELETE FROM sessions WHERE token = $1", [token]).catch(() => {});
  setCookie(res, "", 0);
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post("/api/password", auth, async (req, res, next) => {
  try {
    const current = String(req.body.current || "");
    const next_ = String(req.body.next || "");
    if (!checkPassword(current, req.user.pass_hash))
      return res.status(400).json({ error: "La contraseña actual no es correcta." });
    if (next_.length < 6) return res.status(400).json({ error: "La nueva contraseña necesita al menos 6 caracteres." });
    await q("UPDATE users SET pass_hash = $2 WHERE id = $1", [req.user.id, hashPassword(next_)]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/* --- datos de cada usuario: rutina, registros, etc. --- */
const KEY_RE = /^[A-Za-z0-9_~-]{1,80}$/;
app.get("/api/docs", auth, async (req, res, next) => {
  try {
    const { rows } = await q("SELECT key, data FROM docs WHERE user_id = $1", [req.user.id]);
    res.json({ docs: rows });
  } catch (e) {
    next(e);
  }
});
app.put("/api/docs/:key", auth, async (req, res, next) => {
  try {
    if (!KEY_RE.test(req.params.key)) return res.status(400).json({ error: "Clave no válida" });
    await q(
      `INSERT INTO docs (user_id, key, data) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [req.user.id, req.params.key, JSON.stringify(req.body || {})]
    );
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
app.delete("/api/docs/:key", auth, async (req, res, next) => {
  try {
    await q("DELETE FROM docs WHERE user_id = $1 AND key = $2", [req.user.id, req.params.key]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/* --- panel de administración --- */
const LOG_RE = /(^|~)log-(\d{4}-\d{2}-\d{2})$/;
function summarizeLog(data) {
  let sets = 0, volume = 0, exercises = 0;
  for (const e of Object.values((data && data.entries) || {})) {
    let has = false;
    for (const s of (e && e.sets) || []) {
      const w = parseFloat(String(s.w).replace(",", ".")), r = parseInt(s.r, 10);
      if (!isNaN(w) && r > 0) { sets++; volume += w * r; has = true; }
    }
    if (has) exercises++;
  }
  return { sets, volume, exercises };
}
const userRow = (u) => ({
  id: u.id, username: u.username, email: u.email, name: u.name, isAdmin: u.is_admin,
  createdAt: u.created_at, lastSeen: u.last_seen,
});
const ymd = (d) => d.toISOString().slice(0, 10);

app.get("/api/admin/overview", auth, admin, async (req, res, next) => {
  try {
    const [{ rows: users }, { rows: logs }, { rows: sess }] = await Promise.all([
      q("SELECT * FROM users ORDER BY created_at"),
      q("SELECT user_id, key, data, updated_at FROM docs WHERE key LIKE '%log-%'"),
      q("SELECT user_id, COUNT(*)::int AS n FROM sessions WHERE created_at > now() - interval '90 days' GROUP BY user_id"),
    ]);
    const byUser = {};
    for (const u of users) byUser[u.id] = { ...userRow(u), workouts: 0, sets: 0, volume: 0, lastWorkout: null, lastActivity: u.last_seen, sessions: 0 };
    for (const s of sess) if (byUser[s.user_id]) byUser[s.user_id].sessions = s.n;
    const today = new Date();
    const days = {};
    for (let i = 29; i >= 0; i--) { const d = new Date(today); d.setUTCDate(d.getUTCDate() - i); days[ymd(d)] = 0; }
    const activity = [];
    let totalSets = 0, totalVolume = 0, totalWorkouts = 0;
    for (const r of logs) {
      const m = LOG_RE.exec(r.key);
      const U = byUser[r.user_id];
      if (!m || !U) continue;
      const date = m[2];
      const sm = summarizeLog(r.data);
      if (!sm.sets) continue;
      totalWorkouts++; totalSets += sm.sets; totalVolume += sm.volume;
      U.workouts++; U.sets += sm.sets; U.volume += sm.volume;
      if (!U.lastWorkout || date > U.lastWorkout) U.lastWorkout = date;
      if (!U.lastActivity || new Date(r.updated_at) > new Date(U.lastActivity)) U.lastActivity = r.updated_at;
      if (date in days) days[date]++;
      activity.push({ userId: r.user_id, name: U.name, username: U.username, date, dayName: (r.data && r.data.dayName) || "", exercises: sm.exercises, sets: sm.sets, volume: Math.round(sm.volume), updatedAt: r.updated_at });
    }
    activity.sort((x, y) => (y.date + y.updatedAt > x.date + x.updatedAt ? 1 : -1));
    const now = Date.now();
    const list = Object.values(byUser);
    const within = (t, d) => t && now - new Date(t).getTime() < d * 86400000;
    res.json({
      stats: {
        users: list.length,
        admins: list.filter((u) => u.isAdmin).length,
        active7: list.filter((u) => within(u.lastActivity, 7)).length,
        active30: list.filter((u) => within(u.lastActivity, 30)).length,
        new7: list.filter((u) => within(u.createdAt, 7)).length,
        workouts: totalWorkouts,
        sets: totalSets,
        volume: Math.round(totalVolume),
      },
      daily: Object.entries(days).map(([date, n]) => ({ date, n })),
      users: list.map((u) => ({ ...u, volume: Math.round(u.volume) })),
      activity: activity.slice(0, 60),
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/admin/users/:id", auth, admin, async (req, res, next) => {
  try {
    const { rows } = await q("SELECT * FROM users WHERE id = $1", [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "Ese usuario ya no existe." });
    const [{ rows: docs }, { rows: s }] = await Promise.all([
      q("SELECT key, data, updated_at FROM docs WHERE user_id = $1", [req.params.id]),
      q("SELECT COUNT(*)::int AS n FROM sessions WHERE user_id = $1 AND created_at > now() - interval '90 days'", [req.params.id]),
    ]);
    res.json({ user: { ...userRow(rows[0]), sessions: s[0].n }, docs });
  } catch (e) {
    next(e);
  }
});

app.post("/api/admin/users", auth, admin, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const name = String(req.body.name || "").trim().slice(0, 60);
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!USER_RE.test(username)) return res.status(400).json({ error: "El usuario debe tener 3 a 30 letras, números, puntos o guiones." });
    if (!name) return res.status(400).json({ error: "Escribe un nombre." });
    if (email && !EMAIL_RE.test(email)) return res.status(400).json({ error: "Ese email no parece válido." });
    if (password.length < 6) return res.status(400).json({ error: "La contraseña necesita al menos 6 caracteres." });
    const dup = await q("SELECT 1 FROM users WHERE username = $1 OR ($2 <> '' AND email = $2)", [username, email]);
    if (dup.rows.length) return res.status(409).json({ error: "Ese usuario o email ya está registrado." });
    const { rows } = await q(
      "INSERT INTO users (username, email, name, pass_hash, is_admin) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [username, email || null, name, hashPassword(password), !!req.body.isAdmin]
    );
    res.json({ user: userRow(rows[0]) });
  } catch (e) {
    next(e);
  }
});

app.patch("/api/admin/users/:id", auth, admin, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const name = String(req.body.name || "").trim().slice(0, 60);
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!USER_RE.test(username)) return res.status(400).json({ error: "El usuario debe tener 3 a 30 letras, números, puntos o guiones." });
    if (!name) return res.status(400).json({ error: "Escribe un nombre." });
    if (email && !EMAIL_RE.test(email)) return res.status(400).json({ error: "Ese email no parece válido." });
    const dup = await q("SELECT 1 FROM users WHERE id <> $1 AND (username = $2 OR ($3 <> '' AND email = $3))", [req.params.id, username, email]);
    if (dup.rows.length) return res.status(409).json({ error: "Ese usuario o email ya lo tiene otra cuenta." });
    await q("UPDATE users SET username = $2, name = $3, email = $4 WHERE id = $1", [req.params.id, username, name, email || null]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

app.post("/api/admin/users/:id/admin", auth, admin, async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: "No puedes quitarte tu propio permiso." });
    await q("UPDATE users SET is_admin = $2 WHERE id = $1", [req.params.id, !!req.body.isAdmin]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
app.post("/api/admin/users/:id/password", auth, admin, async (req, res, next) => {
  try {
    const pw = String(req.body.password || "");
    if (pw.length < 6) return res.status(400).json({ error: "La contraseña necesita al menos 6 caracteres." });
    await q("UPDATE users SET pass_hash = $2 WHERE id = $1", [req.params.id, hashPassword(pw)]);
    if (req.params.id !== req.user.id) await q("DELETE FROM sessions WHERE user_id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
app.post("/api/admin/users/:id/logout", auth, admin, async (req, res, next) => {
  try {
    const token = readCookie(req);
    await q("DELETE FROM sessions WHERE user_id = $1 AND token <> $2", [req.params.id, token || ""]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
app.delete("/api/admin/users/:id", auth, admin, async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: "No puedes borrar tu propia cuenta." });
    await q("DELETE FROM users WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

app.get("/healthz", (req, res) => res.send("ok"));
app.use("/api", (req, res) => res.status(404).json({ error: "No encontrado" }));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h" }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Algo ha fallado en el servidor. Inténtalo de nuevo." });
});

migrate()
  .then(() => app.listen(PORT, () => console.log(`Liftlog escuchando en el puerto ${PORT}`)))
  .catch((e) => {
    console.error("No se pudo preparar la base de datos", e);
    process.exit(1);
  });
