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
  await q(`CREATE TABLE IF NOT EXISTS friends (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    friend_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, friend_id)
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
app.use(express.json({ limit: "3mb" }));

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
const MAX_DOC = 2 * 1024 * 1024;
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

/* --- recordatorios (.ics) y exportar historial (.csv) --- */
const ICS_DAY = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"];
const pad2 = (n) => String(n).padStart(2, "0");
const icsText = (t) => String(t || "").replace(/\\/g, "\\\\").replace(/[,;]/g, " ").replace(/\n/g, "\\n");
app.get("/api/reminders.ics", auth, async (req, res, next) => {
  try {
    const { rows } = await q("SELECT data FROM docs WHERE user_id = $1 AND key = 'routine'", [req.user.id]);
    const days = (rows[0] && rows[0].data && rows[0].data.days) || [];
    const m = /^(\d{1,2}):(\d{2})$/.exec(String(req.query.time || "18:00")) || [0, "18", "00"];
    const hh = Math.min(23, +m[1]), mm = Math.min(59, +m[2]);
    const now = new Date();
    const stamp = now.toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
    const ev = [];
    for (const d of days) {
      const wd = (d.wd || []).filter((w) => w >= 0 && w <= 6);
      if (!wd.length) continue;
      let first = new Date(now);
      for (let i = 0; i < 7; i++) { const t = new Date(now); t.setDate(now.getDate() + i); if (wd.includes(t.getDay())) { first = t; break; } }
      const ymd = `${first.getFullYear()}${pad2(first.getMonth() + 1)}${pad2(first.getDate())}`;
      ev.push([
        "BEGIN:VEVENT", `UID:liftlog-${d.id}-${req.user.id}@liftlog-gym`, `DTSTAMP:${stamp}`,
        `DTSTART;TZID=Europe/Madrid:${ymd}T${pad2(hh)}${pad2(mm)}00`, `DTEND;TZID=Europe/Madrid:${ymd}T${pad2((hh + 1) % 24)}${pad2(mm)}00`,
        `RRULE:FREQ=WEEKLY;BYDAY=${wd.map((w) => ICS_DAY[w]).join(",")}`,
        `SUMMARY:Gym · ${icsText(d.name)}`,
        `DESCRIPTION:${icsText((d.ex || []).map((x) => `${x.name} ${x.sets}x${x.reps}`).join("\n"))}`,
        "BEGIN:VALARM", "ACTION:DISPLAY", "DESCRIPTION:Hoy toca gym", "TRIGGER:-PT30M", "END:VALARM", "END:VEVENT",
      ].join("\r\n"));
    }
    const tz = ["BEGIN:VTIMEZONE", "TZID:Europe/Madrid", "BEGIN:STANDARD", "DTSTART:19701025T030000", "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU", "TZOFFSETFROM:+0200", "TZOFFSETTO:+0100", "END:STANDARD", "BEGIN:DAYLIGHT", "DTSTART:19700329T020000", "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU", "TZOFFSETFROM:+0100", "TZOFFSETTO:+0200", "END:DAYLIGHT", "END:VTIMEZONE"].join("\r\n");
    const body = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Liftlog//ES", "CALSCALE:GREGORIAN", "METHOD:PUBLISH", "X-WR-CALNAME:Liftlog", tz, ...ev, "END:VCALENDAR"].join("\r\n");
    res.setHeader("Content-Type", "text/calendar; charset=utf-8");
    res.setHeader("Content-Disposition", 'inline; filename="liftlog-recordatorios.ics"');
    res.send(body);
  } catch (e) {
    next(e);
  }
});
app.get("/api/export.csv", auth, async (req, res, next) => {
  try {
    const { rows } = await q("SELECT key, data FROM docs WHERE user_id = $1 AND key ~ '^log-\\d{4}-\\d{2}-\\d{2}$' ORDER BY key", [req.user.id]);
    const cell = (v) => { const s = String(v ?? ""); return /[;"\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const kg = (n) => (Math.round(n * 100) / 100).toString().replace(".", ",");
    const out = [["Fecha", "Rutina", "Ejercicio", "Serie", "Kg", "Repeticiones", "Volumen (kg)"]];
    for (const r of rows) {
      const L = r.data || {};
      for (const e of Object.values(L.entries || {})) {
        let i = 0;
        for (const s of (e && e.sets) || []) {
          const w = parseFloat(String(s.w).replace(",", ".")), rep = parseInt(s.r, 10);
          if (isNaN(w) || !(rep > 0)) continue;
          out.push([r.key.slice(4), L.dayName || "", e.name || "", ++i, kg(w), rep, kg(w * rep)]);
        }
      }
    }
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="liftlog-historial-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send("﻿" + out.map((r) => r.map(cell).join(";")).join("\r\n"));
  } catch (e) {
    next(e);
  }
});

/* --- amigos --- */
// user_id envía la solicitud a friend_id. Aceptada = status 'accepted'.
async function friendIds(uid) {
  const { rows } = await q(
    `SELECT CASE WHEN user_id = $1 THEN friend_id ELSE user_id END AS id FROM friends
     WHERE (user_id = $1 OR friend_id = $1) AND status = 'accepted'`, [uid]);
  return rows.map((r) => r.id);
}
app.get("/api/friends", auth, async (req, res, next) => {
  try {
    const uid = req.user.id;
    const { rows } = await q(
      `SELECT f.user_id, f.friend_id, f.status, u.id, u.name, u.username
       FROM friends f JOIN users u ON u.id = CASE WHEN f.user_id = $1 THEN f.friend_id ELSE f.user_id END
       WHERE f.user_id = $1 OR f.friend_id = $1`, [uid]);
    const ids = rows.filter((r) => r.status === "accepted").map((r) => r.id);
    const stats = {};
    if (ids.length) {
      const st = await q("SELECT user_id, data FROM docs WHERE key = 'stats' AND user_id = ANY($1::uuid[])", [ids]);
      for (const r of st.rows) stats[r.user_id] = r.data;
    }
    const pick = (r) => ({ id: r.id, name: r.name, username: r.username });
    res.json({
      friends: rows.filter((r) => r.status === "accepted").map((r) => ({ ...pick(r), stats: stats[r.id] || null })),
      incoming: rows.filter((r) => r.status === "pending" && r.friend_id === uid).map(pick),
      outgoing: rows.filter((r) => r.status === "pending" && r.user_id === uid).map(pick),
    });
  } catch (e) {
    next(e);
  }
});
app.post("/api/friends", auth, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase().replace(/^@/, "");
    const { rows } = await q("SELECT id FROM users WHERE username = $1", [username]);
    if (!rows.length) return res.status(404).json({ error: "No hay nadie con ese usuario. Revisa cómo se escribe." });
    const fid = rows[0].id;
    if (fid === req.user.id) return res.status(400).json({ error: "Ese eres tú." });
    const ex = await q("SELECT user_id, status FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)", [req.user.id, fid]);
    if (ex.rows.length) {
      const r = ex.rows[0];
      if (r.status === "accepted") return res.json({ status: "accepted" });
      if (r.user_id === fid) {
        await q("UPDATE friends SET status = 'accepted' WHERE user_id = $1 AND friend_id = $2", [fid, req.user.id]);
        return res.json({ status: "accepted" });
      }
      return res.status(409).json({ error: "Ya le enviaste una solicitud." });
    }
    await q("INSERT INTO friends (user_id, friend_id) VALUES ($1, $2)", [req.user.id, fid]);
    res.json({ status: "pending" });
  } catch (e) {
    next(e);
  }
});
app.post("/api/friends/:id/accept", auth, async (req, res, next) => {
  try {
    const r = await q("UPDATE friends SET status = 'accepted' WHERE user_id = $1 AND friend_id = $2 AND status = 'pending'", [req.params.id, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: "Esa solicitud ya no existe." });
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
app.delete("/api/friends/:id", auth, async (req, res, next) => {
  try {
    await q("DELETE FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)", [req.user.id, req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
app.get("/api/feed", auth, async (req, res, next) => {
  try {
    const ids = [req.user.id, ...(await friendIds(req.user.id))];
    const { rows } = await q(
      `SELECT d.user_id, d.key, d.data, d.updated_at, u.name, u.username FROM docs d JOIN users u ON u.id = d.user_id
       WHERE d.user_id = ANY($1::uuid[]) AND d.key ~ '(^|~)log-\\d{4}-\\d{2}-\\d{2}$'
       AND substring(d.key from '\\d{4}-\\d{2}-\\d{2}$') >= to_char(now() - interval '30 days', 'YYYY-MM-DD')`, [ids]);
    const feed = [];
    for (const r of rows) {
      const sm = summarizeLog(r.data);
      if (!sm.sets) continue;
      feed.push({ me: r.user_id === req.user.id, name: r.name, username: r.username, date: r.key.slice(-10),
        dayName: (r.data && r.data.dayName) || "", exercises: sm.exercises, sets: sm.sets, volume: Math.round(sm.volume), updatedAt: r.updated_at });
    }
    feed.sort((a, b) => (b.date + b.updatedAt > a.date + a.updatedAt ? 1 : -1));
    res.json({ feed: feed.slice(0, 40) });
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

const BUILD = process.env.RENDER_GIT_COMMIT || String(Date.now());
app.get("/api/version", (req, res) => { noCacheHdr(res); res.json({ build: BUILD }); });
app.get("/healthz", (req, res) => res.send("ok"));
app.use("/api", (req, res) => res.status(404).json({ error: "No encontrado" }));
// La página y el manifest nunca se guardan en caché: así cada cambio llega al momento.
const noCache = (res) => noCacheHdr(res);
function noCacheHdr(res) {
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}
app.use(
  express.static(path.join(__dirname, "public"), {
    etag: true,
    setHeaders: (res, file) => {
      if (/\.(html|json)$/.test(file)) noCache(res);
      else res.setHeader("Cache-Control", "public, max-age=86400");
    },
  })
);
app.get("*", (req, res) => {
  noCache(res);
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

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
