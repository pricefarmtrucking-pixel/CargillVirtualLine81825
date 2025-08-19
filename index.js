// index.js  — CommonJS backend for Cargill Soybean — Virtual Line
// Run with: node index.js
// NOTE: package.json must NOT contain { "type": "module" } for CommonJS.

require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { customAlphabet } = require('nanoid');
const Database = require('better-sqlite3');

// ---------- Config ----------
const app = express();
const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DB_PATH = process.env.DB_PATH || 'data.db';
const CORS_ORIGIN = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);

// Sessions stored in SQLite (simple)
const SESSION_COOKIE = 'sid';
const SESSION_TTL_MIN = 7 * 24 * 60; // 7 days

// OTP settings
const OTP_TTL_MIN = 10;
const OTP_ATTEMPTS = 5;

// Twilio (optional)
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN  || '';
const TWILIO_FROM        = process.env.TWILIO_PHONE_NUMBER || '';
let twilioClient = null;
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
  try {
    twilioClient = require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    console.log('Twilio: client initialized');
  } catch (e) {
    console.warn('Twilio init failed; continuing without SMS:', e?.message || e);
  }
}

// ---------- Middleware ----------
app.use(bodyParser.json());
app.use(cookieParser());

// CORS (credentials)
const corsOptions = {
  origin: function (origin, cb) {
    if (!origin) return cb(null, true); // allow same-origin / curl
    if (CORS_ORIGIN.length === 0) return cb(null, true);
    return cb(null, CORS_ORIGIN.includes(origin));
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ---------- Database ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Minimal safety: ensure critical columns exist if migrate.js was skipped
(function ensureMinimalSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      phone TEXT NOT NULL,
      role TEXT DEFAULT 'driver',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      attempts_left INTEGER DEFAULT 5,
      consumed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS time_slots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      slot_time TEXT NOT NULL,
      is_workin INTEGER DEFAULT 0,
      reserved_truck_id INTEGER,
      reserved_at TEXT,
      hold_token TEXT,
      hold_expires_at TEXT,
      UNIQUE(site_id, date, slot_time, is_workin)
    );
    CREATE TABLE IF NOT EXISTS slot_reservations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      slot_time TEXT NOT NULL,
      truck_id TEXT,
      license_plate TEXT,
      driver_name TEXT,
      driver_phone TEXT,
      vendor_name TEXT,
      farm_or_ticket TEXT,
      est_amount REAL,
      est_unit TEXT,
      manage_token TEXT,
      queue_code TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
  // Ensure probe index
  db.exec(`CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations (site_id, date, queue_code);`);
})();

// ---------- Helpers ----------
const nano = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', 24);
const genManageToken = () => nano();

const code6 = customAlphabet('0123456789', 6);
const genOtp = () => code6();

const code4 = customAlphabet('0123456789', 4);
const genProbeCode = () => code4();

function nowISO() { return new Date().toISOString(); }
function plusMinutesISO(m) { return new Date(Date.now() + m * 60000).toISOString(); }

function normalizePhone(raw) {
  const d = String(raw || '').replace(/\D/g, '');
  if (/^\d{10}$/.test(d)) return '+1' + d;
  const m = d.match(/^1?(\d{10})$/);
  return m ? '+1' + m[1] : null;
}

function setSessionCookie(res, token) {
  const secure = NODE_ENV !== 'development';
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    maxAge: SESSION_TTL_MIN * 60 * 1000,
    path: '/'
  });
}

function sendSMS(to, body) {
  if (!to) return Promise.resolve({ ok: false, reason: 'missing to' });
  if (twilioClient && TWILIO_FROM) {
    return twilioClient.messages
      .create({ to, from: TWILIO_FROM, body })
      .then(m => ({ ok: true, sid: m.sid }))
      .catch(err => ({ ok: false, error: err?.message || String(err) }));
  }
  console.log('[SMS MOCK]', to, body);
  return Promise.resolve({ ok: true, mocked: true });
}

// ---------- Auth (OTP) ----------
app.post('/auth/request-code', async (req, res) => {
  try {
    const { phone: raw, role } = req.body || {};
    const phone = normalizePhone(raw);
    if (!phone) return res.status(400).json({ ok: false, error: 'invalid_phone' });

    const code = genOtp();
    const expires = plusMinutesISO(OTP_TTL_MIN);

    db.prepare(`
      INSERT INTO otp_codes (phone, code, expires_at, attempts_left)
      VALUES (?, ?, ?, ?)
    `).run(phone, code, expires, OTP_ATTEMPTS);

    const who = (role === 'admin' || role === 'probe') ? role.toUpperCase() : 'Login';
    const msg = `Cargill: ${who} code ${code}. Expires in ${OTP_TTL_MIN} min. Reply STOP to opt out.`;
    const sms = await sendSMS(phone, msg);

    return res.json({ ok: true, sms });
  } catch (e) {
    console.error('/auth/request-code failed', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/auth/verify', (req, res) => {
  try {
    const { phone: raw, code, role } = req.body || {};
    const phone = normalizePhone(raw);
    if (!phone) return res.status(400).json({ ok: false, error: 'invalid_phone' });
    if (!/^\d{6}$/.test(code || '')) return res.status(400).json({ ok: false, error: 'invalid_code' });

    const row = db.prepare(`
      SELECT * FROM otp_codes
      WHERE phone = ? AND code = ? AND (consumed_at IS NULL)
      ORDER BY id DESC
      LIMIT 1
    `).get(phone, code);

    if (!row) return res.status(400).json({ ok: false, error: 'not_found' });

    const now = new Date();
    if (new Date(row.expires_at).getTime() < now.getTime()) {
      return res.status(400).json({ ok: false, error: 'expired' });
    }
    if (row.attempts_left <= 0) {
      return res.status(400).json({ ok: false, error: 'locked' });
    }

    // consume/dec attempts atomically
    db.prepare(`UPDATE otp_codes SET consumed_at = ?, attempts_left = attempts_left - 1 WHERE id = ?`)
      .run(nowISO(), row.id);

    // create session
    const token = nano();
    const safeRole = (role === 'admin' || role === 'probe') ? role : 'driver';
    db.prepare(`INSERT INTO sessions (token, phone, role, created_at) VALUES (?, ?, ?, ?)`)
      .run(token, phone, safeRole, nowISO());

    setSessionCookie(res, token);
    return res.json({ ok: true, role: safeRole, token });
  } catch (e) {
    console.error('/auth/verify failed', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

function requireSession(req, res, next) {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return res.status(401).json({ ok: false, error: 'no_session' });
  const s = db.prepare(`SELECT * FROM sessions WHERE token = ?`).get(token);
  if (!s) return res.status(401).json({ ok: false, error: 'invalid_session' });
  req.session = s;
  next();
}

// ---------- Slots & Appointments ----------
/**
 * GET /api/slots?site=<id>&date=YYYY-MM-DD
 * Returns all time_slots for that day with simple status.
 */
app.get('/api/slots', requireSession, (req, res) => {
  try {
    const site = Number(req.query.site || 1);
    const date = String(req.query.date || '').slice(0, 10);
    if (!date) return res.status(400).json({ ok: false, error: 'missing_date' });

    const slots = db.prepare(`
      SELECT t.id, t.site_id, t.date, t.slot_time,
             COALESCE(
               (SELECT 1 FROM slot_reservations r
                WHERE r.site_id = t.site_id AND r.date = t.date AND r.slot_time = t.slot_time
                LIMIT 1), 0
             ) AS is_reserved
      FROM time_slots t
      WHERE t.site_id = ? AND t.date = ?
      ORDER BY time(t.slot_time)
    `).all(site, date);

    return res.json({ ok: true, slots });
  } catch (e) {
    console.error('/api/slots failed', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/**
 * GET /api/appointments?site=<id>&date=YYYY-MM-DD
 * Returns joined reservations (one row per slot, including open ones if present).
 */
app.get('/api/appointments', requireSession, (req, res) => {
  try {
    const site = Number(req.query.site || 1);
    const date = String(req.query.date || '').slice(0, 10);
    if (!date) return res.status(400).json({ ok: false, error: 'missing_date' });

    // base set of slots for the day
    const slots = db.prepare(`
      SELECT id, site_id, date, slot_time
      FROM time_slots
      WHERE site_id = ? AND date = ?
      ORDER BY time(slot_time)
    `).all(site, date);

    // map reservations by key
    const resvs = db.prepare(`
      SELECT *
      FROM slot_reservations
      WHERE site_id = ? AND date = ?
    `).all(site, date);

    const map = new Map();
    for (const r of resvs) {
      map.set(`${r.site_id}::${r.date}::${r.slot_time}`, r);
    }

    const rows = slots.map(s => {
      const r = map.get(`${s.site_id}::${s.date}::${s.slot_time}`);
      if (!r) {
        return {
          time: s.slot_time,
          site_id: s.site_id,
          date: s.date,
          status: 'Open',
          actions: ['assign']
        };
      }
      return {
        reservation_id: r.id,
        time: r.slot_time,
        site_id: r.site_id,
        date: r.date,
        driver: r.driver_name || '',
        plate: r.license_plate || '',
        vendor: r.vendor_name || '',
        farm_ticket: r.farm_or_ticket || '',
        est_amount: r.est_amount || null,
        est_unit: r.est_unit || '',
        phone: r.driver_phone || '',
        probe_code: r.queue_code || '',
        status: 'Reserved',
        actions: ['reassign', 'cancel']
      };
    });

    return res.json({ ok: true, appointments: rows });
  } catch (e) {
    console.error('/api/appointments failed', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/**
 * POST /api/slots/reserve
 * Body: { site_id, date, slot_time, driver_name, license_plate, vendor_name, farm_or_ticket, est_amount, est_unit, driver_phone }
 * Creates reservation + probe_code and sends confirmation SMS.
 */
app.post('/api/slots/reserve', requireSession, async (req, res) => {
  try {
    const b = req.body || {};
    const site_id = Number(b.site_id);
    const date = String(b.date || '').slice(0, 10);
    const slot_time = String(b.slot_time || '').slice(0, 5);
    const driver_phone = normalizePhone(b.driver_phone);
    const driver_name = (b.driver_name || '').trim();
    const license_plate = (b.license_plate || '').trim();
    const vendor_name = (b.vendor_name || '').trim();
    const farm_or_ticket = (b.farm_or_ticket || '').trim();
    const est_amount = b.est_amount == null ? null : Number(b.est_amount);
    const est_unit = (b.est_unit || '').trim();

    if (!site_id || !date || !slot_time) {
      return res.status(400).json({ ok: false, error: 'missing_slot_fields' });
    }

    // Check if slot exists
    const slot = db.prepare(`
      SELECT id FROM time_slots WHERE site_id=? AND date=? AND slot_time=? LIMIT 1
    `).get(site_id, date, slot_time);
    if (!slot) return res.status(400).json({ ok: false, error: 'slot_not_found' });

    // Check if reserved
    const existing = db.prepare(`
      SELECT id FROM slot_reservations WHERE site_id=? AND date=? AND slot_time=? LIMIT 1
    `).get(site_id, date, slot_time);
    if (existing) return res.status(409).json({ ok: false, error: 'slot_reserved' });

    const manage_token = genManageToken();
    const probe_code = genProbeCode();

    const result = db.prepare(`
      INSERT INTO slot_reservations
        (site_id, date, slot_time, truck_id, license_plate, driver_name, driver_phone,
         vendor_name, farm_or_ticket, est_amount, est_unit, manage_token, queue_code, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      site_id, date, slot_time, null, license_plate, driver_name, driver_phone,
      vendor_name, farm_or_ticket, est_amount, est_unit, manage_token, probe_code, nowISO()
    );

    // SMS confirmation
    if (driver_phone) {
      const msg = `Cargill: Confirmed ${date} at ${slot_time} (EAST/WEST). Code ${probe_code}. Reply STOP to opt out.`;
      await sendSMS(driver_phone, msg);
    }

    return res.json({
      ok: true,
      reservation: {
        id: result.lastInsertRowid,
        site_id, date, slot_time,
        driver_name, license_plate, vendor_name, farm_or_ticket,
        est_amount, est_unit, driver_phone,
        probe_code,
        manage_token
      }
    });
  } catch (e) {
    console.error('/api/slots/reserve failed', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/**
 * POST /api/slots/reassign
 * Body: { reservation_id, to_slot_time }
 * Returns probe_code in response.
 */
app.post('/api/slots/reassign', requireSession, (req, res) => {
  try {
    const { reservation_id, to_slot_time } = req.body || {};
    if (!reservation_id || !to_slot_time) {
      return res.status(400).json({ ok: false, error: 'missing_fields' });
    }

    const r = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(Number(reservation_id));
    if (!r) return res.status(404).json({ ok: false, error: 'not_found' });

    // check target slot exists and is open
    const slot = db.prepare(`SELECT id FROM time_slots WHERE site_id=? AND date=? AND slot_time=? LIMIT 1`)
      .get(r.site_id, r.date, String(to_slot_time).slice(0,5));
    if (!slot) return res.status(400).json({ ok: false, error: 'slot_not_found' });

    const conflict = db.prepare(`SELECT id FROM slot_reservations WHERE site_id=? AND date=? AND slot_time=? LIMIT 1`)
      .get(r.site_id, r.date, String(to_slot_time).slice(0,5));
    if (conflict) return res.status(409).json({ ok: false, error: 'slot_reserved' });

    db.prepare(`UPDATE slot_reservations SET slot_time=? WHERE id=?`)
      .run(String(to_slot_time).slice(0,5), r.id);

    return res.json({ ok: true, reservation_id: r.id, probe_code: r.queue_code });
  } catch (e) {
    console.error('/api/slots/reassign failed', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/**
 * POST /api/slots/cancel
 * Body: { reservation_id }
 * Returns probe_code in response.
 */
app.post('/api/slots/cancel', requireSession, (req, res) => {
  try {
    const { reservation_id } = req.body || {};
    if (!reservation_id) return res.status(400).json({ ok: false, error: 'missing_fields' });

    const r = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(Number(reservation_id));
    if (!r) return res.status(404).json({ ok: false, error: 'not_found' });

    db.prepare(`DELETE FROM slot_reservations WHERE id=?`).run(r.id);
    return res.json({ ok: true, reservation_id: r.id, probe_code: r.queue_code });
  } catch (e) {
    console.error('/api/slots/cancel failed', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ---------- Misc ----------
app.get('/whoami', requireSession, (req, res) => {
  res.json({ ok: true, session: { phone: req.session.phone, role: req.session.role } });
});

app.get('/health', (req, res) => {
  res.json({ ok: true, time: nowISO() });
});

// ---------- Static ----------
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`CORS origin: ${CORS_ORIGIN.length ? CORS_ORIGIN.join(', ') : '(any)'}`);
});
