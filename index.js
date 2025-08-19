// index.js  —  CommonJS backend for Cargill Soy Virtual Line
// Run: node index.js

require('dotenv').config();

const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Database = require('better-sqlite3');
const { nanoid } = require('nanoid');

// ---------- Config ----------
const PORT = process.env.PORT || 10000;
const DB_PATH = process.env.DB_PATH || 'data.db';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const CORS_ORIGIN = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// ---------- CORS (with credentials) ----------
const corsMw = cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // allow same-origin/direct
    if (CORS_ORIGIN.length === 0) return cb(null, true); // permissive if not set
    if (CORS_ORIGIN.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key'],
});

// ---------- DB ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Minimal idempotent schema (won't clash with migrate.js)
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  phone TEXT PRIMARY KEY,
  last_login_at TEXT,
  is_banned INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
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
CREATE TABLE IF NOT EXISTS site_settings (
  site_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  loads_target INTEGER NOT NULL,
  open_time TEXT NOT NULL,
  close_time TEXT NOT NULL,
  workins_per_hour INTEGER DEFAULT 0,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (site_id, date)
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
  queue_code TEXT, -- 4-digit Probe Code
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_slots ON time_slots(site_id, date, slot_time);
CREATE INDEX IF NOT EXISTS idx_resv_lookup ON slot_reservations(site_id, date, slot_time);
CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations(site_id, date, queue_code);
CREATE TABLE IF NOT EXISTS facility_info (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  facility_phone TEXT,
  support_phone TEXT,
  updated_at TEXT
);
INSERT OR IGNORE INTO facility_info (id) VALUES (1);
`);

// ---------- Twilio (optional) ----------
let twilioClient = null;
const hasTwilio =
  !!process.env.TWILIO_ACCOUNT_SID &&
  !!process.env.TWILIO_AUTH_TOKEN &&
  (!!process.env.TWILIO_PHONE_NUMBER || !!process.env.TWILIO_MESSAGING_SERVICE_SID);

if (hasTwilio) {
  twilioClient = require('twilio')(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
  );
  console.log('Twilio: client initialized');
} else {
  console.log('Twilio: not configured, using console mock');
}

async function sendSMS(to, body) {
  if (!hasTwilio) {
    console.log('[MOCK SMS]', to, body);
    return { sent: true, sid: 'mock-' + nanoid(8) };
  }
  const payload = {
    to,
    body,
  };
  if (process.env.TWILIO_MESSAGING_SERVICE_SID) {
    payload.messagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID;
  } else {
    payload.from = process.env.TWILIO_PHONE_NUMBER;
  }
  try {
    const msg = await twilioClient.messages.create(payload);
    return { sent: true, sid: msg.sid };
  } catch (e) {
    console.error('SMS ERROR:', e?.message || e);
    return { sent: false, error: e?.message || String(e) };
  }
}

// ---------- Helpers ----------
const SITES = [
  { id: 1, name: 'East' },
  { id: 2, name: 'West' },
];
const siteName = (id) => (SITES.find(s => s.id === Number(id))?.name || `Site ${id}`);

const app = express();
app.set('trust proxy', 1);
app.use(corsMw);
app.use(bodyParser.json());

// cookie helper (no cookie-parser needed to set)
function setSessionCookie(res, token) {
  res.cookie('session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });
}

const normalizePhone = (p) => {
  const d = String(p || '').replace(/\D/g, '');
  if (/^\d{10}$/.test(d)) return '+1' + d;
  const m = d.match(/^1?(\d{10})$/);
  return m ? '+1' + m[1] : null;
};
const random6 = () => String(Math.floor(100000 + Math.random() * 900000));
const random4 = () => String(Math.floor(1000 + Math.random() * 9000));

// ---------- Auth (OTP) ----------
app.post('/auth/request-code', async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const role = (req.body?.role || '').toLowerCase(); // 'admin' or ''
    if (!phone) return res.status(400).json({ ok: false, error: 'Invalid phone' });

    const code = random6();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    db.prepare(
      `INSERT INTO otp_codes (phone, code, expires_at, attempts_left)
       VALUES (?, ?, ?, 5)`
    ).run(phone, code, expiresAt);

    const smsText =
      role === 'admin'
        ? `Cargill Admin code: ${code}. Valid 5 min. Reply STOP to opt out.`
        : `Cargill code: ${code}. Valid 5 min. Reply STOP to opt out.`;

    const sms = await sendSMS(phone, smsText);

    return res.json({ ok: true, sms });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/auth/verify', (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || '').trim();
    if (!phone || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ ok: false, error: 'Invalid phone/code' });
    }

    const nowIso = new Date().toISOString();
    const row = db
      .prepare(
        `SELECT * FROM otp_codes
         WHERE phone = ? AND code = ? AND consumed_at IS NULL
           AND expires_at > ?
           AND attempts_left > 0
         ORDER BY id DESC LIMIT 1`
      )
      .get(phone, code, nowIso);

    if (!row) {
      // decrement attempts for newest active code for that phone
      db.prepare(
        `UPDATE otp_codes
           SET attempts_left = MAX(attempts_left - 1, 0)
         WHERE phone = ? AND consumed_at IS NULL AND expires_at > ?`
      ).run(phone, nowIso);
      return res.status(401).json({ ok: false, error: 'invalid_or_expired' });
    }

    db.prepare(`UPDATE otp_codes SET consumed_at = ? WHERE id = ?`).run(nowIso, row.id);

    // create session
    const token = nanoid(24);
    db.prepare(`INSERT INTO sessions (token, phone) VALUES (?, ?)`).run(token, phone);
    setSessionCookie(res, token);

    // upsert user record
    db.prepare(
      `INSERT INTO users (phone, last_login_at) VALUES (?, ?)
       ON CONFLICT(phone) DO UPDATE SET last_login_at=excluded.last_login_at`
    ).run(phone, nowIso);

    return res.json({ ok: true, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ---------- Sites & Slots ----------
app.get('/api/sites', (req, res) => {
  res.json({ ok: true, sites: SITES });
});

// GET /api/slots?site=1&date=YYYY-MM-DD
// returns array of {time, status:'open'|'reserved', reservation?}
app.get('/api/slots', (req, res) => {
  try {
    const site = Number(req.query.site || 1);
    const date = String(req.query.date || '').slice(0, 10);
    if (!date) return res.status(400).json({ ok: false, error: 'date_required' });

    const times = db
      .prepare(
        `SELECT t.site_id, t.date, t.slot_time,
                r.id as reservation_id, r.driver_name, r.license_plate, r.vendor_name,
                r.farm_or_ticket, r.est_amount, r.est_unit, r.driver_phone, r.queue_code
           FROM time_slots t
           LEFT JOIN slot_reservations r
                  ON r.site_id=t.site_id AND r.date=t.date AND r.slot_time=t.slot_time
          WHERE t.site_id = ? AND t.date = ?
          ORDER BY t.slot_time`
      )
      .all(site, date);

    const out = times.map((row) => ({
      time: row.slot_time,
      status: row.reservation_id ? 'reserved' : 'open',
      reservation: row.reservation_id
        ? {
            id: row.reservation_id,
            driver_name: row.driver_name,
            license_plate: row.license_plate,
            vendor_name: row.vendor_name,
            farm_or_ticket: row.farm_or_ticket,
            est_amount: row.est_amount,
            est_unit: row.est_unit,
            driver_phone: row.driver_phone,
            probe_code: row.queue_code || null,
          }
        : null,
    }));

    res.json({ ok: true, site, date, slots: out });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// GET /api/appointments?site=1&date=YYYY-MM-DD
// returns rows for facility-appointments page (reserved only)
app.get('/api/appointments', (req, res) => {
  try {
    const site = Number(req.query.site || 1);
    const date = String(req.query.date || '').slice(0, 10);
    if (!date) return res.status(400).json({ ok: false, error: 'date_required' });

    const rows = db
      .prepare(
        `SELECT r.id, r.site_id, r.date, r.slot_time,
                r.driver_name, r.license_plate, r.vendor_name, r.farm_or_ticket,
                r.est_amount, r.est_unit, r.driver_phone, r.queue_code
           FROM slot_reservations r
          WHERE r.site_id = ? AND r.date = ?
          ORDER BY r.slot_time`
      )
      .all(site, date);

    res.json({
      ok: true,
      site,
      date,
      items: rows.map((r) => ({
        id: r.id,
        time: r.slot_time,
        driver: r.driver_name,
        plate: r.license_plate,
        vendor: r.vendor_name,
        farm_ticket: r.farm_or_ticket,
        est_amt: r.est_amount,
        est_unit: r.est_unit,
        phone: r.driver_phone,
        probe_code: r.queue_code || null,
        status: 'reserved',
      })),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Reserve a slot (driver flow or admin)
// Body: {site_id, date, slot_time, driver_name, license_plate, vendor_name, farm_or_ticket, est_amount, est_unit, driver_phone}
app.post('/api/slots/reserve', async (req, res) => {
  try {
    const b = req.body || {};
    const site_id = Number(b.site_id);
    const date = String(b.date || '').slice(0, 10);
    const slot_time = String(b.slot_time || '');

    if (!site_id || !date || !slot_time) {
      return res.status(400).json({ ok: false, error: 'missing_required_fields' });
    }

    // ensure slot exists
    const slot = db
      .prepare(
        `SELECT id FROM time_slots WHERE site_id=? AND date=? AND slot_time=? LIMIT 1`
      )
      .get(site_id, date, slot_time);
    if (!slot) return res.status(404).json({ ok: false, error: 'slot_not_found' });

    // ensure not already reserved
    const taken = db
      .prepare(
        `SELECT id FROM slot_reservations WHERE site_id=? AND date=? AND slot_time=? LIMIT 1`
      )
      .get(site_id, date, slot_time);
    if (taken) return res.status(409).json({ ok: false, error: 'slot_already_reserved' });

    const phone = normalizePhone(b.driver_phone);
    const probeCode = random4();

    const manage_token = nanoid(20);
    const info = db
      .prepare(
        `INSERT INTO slot_reservations
          (site_id,date,slot_time,truck_id,license_plate,driver_name,driver_phone,
           vendor_name,farm_or_ticket,est_amount,est_unit,manage_token,queue_code)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
      )
      .run(
        site_id,
        date,
        slot_time,
        b.truck_id || null,
        b.license_plate || null,
        b.driver_name || null,
        phone || null,
        b.vendor_name || null,
        b.farm_or_ticket || null,
        b.est_amount || null,
        b.est_unit || null,
        manage_token,
        probeCode
      );

    const siteLabel = siteName(site_id);
    if (phone) {
      const text = `Cargill: Confirmed ${date} at ${slot_time} (${siteLabel}). ` +
        `Probe Code ${probeCode}. Reply STOP to opt out.`;
      await sendSMS(phone, text);
    }

    return res.json({
      ok: true,
      reservation: {
        id: info.lastInsertRowid,
        site_id,
        date,
        slot_time,
        probe_code: probeCode,
        manage_token,
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Reassign reservation to a different time
// Body: { reservation_id, to_slot_time }
app.post('/api/slots/reassign', async (req, res) => {
  try {
    const id = Number(req.body?.reservation_id);
    const toTime = String(req.body?.to_slot_time || '');
    if (!id || !toTime) return res.status(400).json({ ok: false, error: 'bad_request' });

    const r = db
      .prepare(`SELECT * FROM slot_reservations WHERE id=? LIMIT 1`)
      .get(id);
    if (!r) return res.status(404).json({ ok: false, error: 'reservation_not_found' });

    // check destination slot
    const slot = db
      .prepare(
        `SELECT id FROM time_slots WHERE site_id=? AND date=? AND slot_time=? LIMIT 1`
      )
      .get(r.site_id, r.date, toTime);
    if (!slot) return res.status(404).json({ ok: false, error: 'target_slot_not_found' });

    // ensure destination not taken
    const taken = db
      .prepare(
        `SELECT id FROM slot_reservations WHERE site_id=? AND date=? AND slot_time=? LIMIT 1`
      )
      .get(r.site_id, r.date, toTime);
    if (taken) return res.status(409).json({ ok: false, error: 'target_slot_unavailable' });

    db.prepare(`UPDATE slot_reservations SET slot_time=? WHERE id=?`).run(toTime, id);

    if (r.driver_phone) {
      const text = `Cargill: Your time was changed to ${r.date} ${toTime} (${siteName(
        r.site_id
      )}). Probe Code ${r.queue_code}. Reply STOP to opt out.`;
      await sendSMS(r.driver_phone, text);
    }

    return res.json({
      ok: true,
      reservation: {
        id,
        site_id: r.site_id,
        date: r.date,
        slot_time: toTime,
        probe_code: r.queue_code,
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Cancel reservation
// Body: { reservation_id }
app.post('/api/slots/cancel', async (req, res) => {
  try {
    const id = Number(req.body?.reservation_id);
    if (!id) return res.status(400).json({ ok: false, error: 'bad_request' });

    const r = db
      .prepare(`SELECT * FROM slot_reservations WHERE id=? LIMIT 1`)
      .get(id);
    if (!r) return res.status(404).json({ ok: false, error: 'reservation_not_found' });

    db.prepare(`DELETE FROM slot_reservations WHERE id=?`).run(id);

    if (r.driver_phone) {
      const text = `Cargill: Your ${r.date} ${r.slot_time} (${siteName(
        r.site_id
      )}) appointment was canceled. Probe Code ${r.queue_code}.`;
      await sendSMS(r.driver_phone, text);
    }

    return res.json({
      ok: true,
      reservation: {
        id,
        site_id: r.site_id,
        date: r.date,
        slot_time: r.slot_time,
        probe_code: r.queue_code,
        status: 'canceled',
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Optional mass cancel: { reservation_ids: [1,2,3] }
app.post('/api/slots/cancel-multiple', async (req, res) => {
  try {
    if (!Array.isArray(req.body?.reservation_ids) || !req.body.reservation_ids.length) {
      return res.status(400).json({ ok: false, error: 'no_ids' });
    }
    const ids = req.body.reservation_ids.map(Number).filter(Boolean);
    const results = [];
    for (const id of ids) {
      const r = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(id);
      if (!r) {
        results.push({ id, ok: false, error: 'not_found' });
        continue;
      }
      db.prepare(`DELETE FROM slot_reservations WHERE id=?`).run(id);
      if (r.driver_phone) {
        await sendSMS(
          r.driver_phone,
          `Cargill: Your ${r.date} ${r.slot_time} (${siteName(
            r.site_id
          )}) appointment was canceled.`
        );
      }
      results.push({ id, ok: true, probe_code: r.queue_code });
    }
    res.json({ ok: true, results });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ---------- Notify-only (admin) ----------
// Body: { phone, message }
// Header: X-Admin-Key: <ADMIN_KEY>
app.post('/api/notify', async (req, res) => {
  try {
    if (!ADMIN_KEY || req.header('X-Admin-Key') !== ADMIN_KEY) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    const phone = normalizePhone(req.body?.phone);
    let message = String(req.body?.message || '').trim();
    if (!phone || !message) return res.status(400).json({ ok: false, error: 'bad_request' });

    // Always append STOP guidance once (if not already present)
    if (!/stop to opt out/i.test(message)) {
      message += ' Reply STOP to opt out.';
    }
    const sms = await sendSMS(phone, message);
    res.json({ ok: true, sms });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ---------- Health ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- Static (public) ----------
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.listen(PORT, () => {
  console.log('Server running on http://localhost:' + PORT);
  console.log('CORS origin:', CORS_ORIGIN.length ? CORS_ORIGIN.join(', ') : '(permissive)');
});
