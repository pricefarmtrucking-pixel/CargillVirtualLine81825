// index.js — Cargill Virtual Line (full)
// Node 18+ / ESM

import express from 'express';
import cookieParser from 'cookie-parser';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import url from 'url';
import cors from 'cors';

// ---------- Setup & ENV ----------
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const app = express();
const db = new Database('data.db');

// Load .env (simple loader for local dev; Render uses process.env)
const ENV = {};
try {
  const txt = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
  for (const line of txt.split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) ENV[m[1]] = m[2];
  }
} catch { /* no local .env */ }

const getEnv = (k, def='') => process.env[k] ?? ENV[k] ?? def;

const ORIGIN = getEnv('CORS_ORIGIN', 'http://localhost:10000'); // e.g. https://cargill-line-1.onrender.com
const SESSION_SECRET = getEnv('SESSION_SECRET', 'dev_secret');

const TWILIO_SID = getEnv('TWILIO_SID');
const TWILIO_AUTH = getEnv('TWILIO_AUTH_TOKEN');
const TWILIO_FROM = getEnv('TWILIO_PHONE_NUMBER');

// Twilio client (optional)
let twilioClient = null;
if (TWILIO_SID && TWILIO_AUTH) {
  try {
    const twilioPkg = await import('twilio');
    twilioClient = twilioPkg.default(TWILIO_SID, TWILIO_AUTH);
    console.log('Twilio: client initialized');
  } catch (e) {
    console.warn('Twilio init failed:', e?.message || e);
  }
} else {
  console.warn('Twilio: missing credentials; SMS will be stubbed');
}

// ---------- Middleware ----------
app.use(express.json());
app.use(cookieParser(SESSION_SECRET));
app.use(
  cors({
    origin: ORIGIN,
    credentials: true,
  })
);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Helpers ----------
function normalizePhone(p) {
  const d = String(p || '').replace(/\D/g, '');
  const m = d.match(/^1?(\d{10})$/);
  return m ? `+1${m[1]}` : null;
}
function minutes(hhmm) {
  const [h, m] = String(hhmm).split(':').map(Number);
  return h * 60 + m;
}
function hhmm(min) {
  return (
    String(Math.floor(min / 60)).padStart(2, '0') +
    ':' +
    String(min % 60).padStart(2, '0')
  );
}
function todayLocalISO() {
  const d = new Date();
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 10);
}
function expireHolds() {
  db.prepare(
    "UPDATE time_slots SET hold_token=NULL, hold_expires_at=NULL WHERE hold_expires_at IS NOT NULL AND hold_expires_at < CURRENT_TIMESTAMP"
  ).run();
}

// ---------- DB bootstrap (minimal) ----------
db.pragma('journal_mode = WAL');
// Create tables if not present
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
  is_workin INTEGER DEFAULT 0, -- 0 regular, 1 work-in
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
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS facility_info (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  facility_phone TEXT,
  support_phone TEXT,
  updated_at TEXT
);
INSERT OR IGNORE INTO facility_info (id) VALUES (1);
`);

// ---------- Auth (OTP) ----------
app.post('/auth/request-code', async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    if (!phone) return res.status(400).json({ error: 'invalid phone' });

    const u = db
      .prepare('SELECT is_banned FROM users WHERE phone=?')
      .get(phone);
    if (u?.is_banned) return res.status(403).json({ error: 'number suspended' });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expires = db.prepare("SELECT datetime('now','+5 minutes') as e").get().e;

    db.prepare(
      'INSERT INTO otp_codes (phone, code, expires_at, attempts_left) VALUES (?,?,?,5)'
    ).run(phone, code, expires);

    // Send SMS
    let sms = { sent: false };
    if (twilioClient && TWILIO_FROM) {
      try {
        const msg = await twilioClient.messages.create({
          from: TWILIO_FROM,
          to: phone,
          body: `Your verification code is ${code}. It expires in 5 minutes. Reply STOP to opt out.`,
        });
        sms = { sent: true, sid: msg.sid, status: msg.status };
      } catch (err) {
        console.warn('Twilio SMS error:', err?.message || err);
        sms = { sent: false, error: 'twilio_error' };
      }
    } else {
      console.log(`[DEV] OTP for ${phone}: ${code}`);
      sms = { sent: true, dev: true };
    }

    return res.json({ ok: true, sms });
  } catch (e) {
    console.error('/auth/request-code', e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/auth/verify', (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || '');
    if (!phone || !/^\d{6}$/.test(code))
      return res.status(400).json({ error: 'bad input' });

    const row = db
      .prepare(
        "SELECT * FROM otp_codes WHERE phone=? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP ORDER BY id DESC LIMIT 1"
      )
      .get(phone);
    if (!row) return res.status(400).json({ error: 'code expired' });
    if (row.attempts_left <= 0)
      return res.status(429).json({ error: 'too many attempts' });

    if (row.code !== code) {
      db.prepare('UPDATE otp_codes SET attempts_left=attempts_left-1 WHERE id=?').run(
        row.id
      );
      return res.status(400).json({ error: 'incorrect code' });
    }

    db.prepare('INSERT OR IGNORE INTO users (phone) VALUES (?)').run(phone);
    db.prepare('UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE phone=?').run(
      phone
    );
    db.prepare('UPDATE otp_codes SET consumed_at=CURRENT_TIMESTAMP WHERE id=?').run(
      row.id
    );

    const token = crypto.randomUUID();
    db.prepare('INSERT INTO sessions (token, phone) VALUES (?,?)').run(token, phone);

    res.cookie('session', token, {
      httpOnly: true,
      sameSite: 'lax', // works from your Render origin
      maxAge: 7 * 24 * 3600 * 1000,
    });
    return res.json({ ok: true });
  } catch (e) {
    console.error('/auth/verify', e);
    return res.status(500).json({ error: 'server error' });
  }
});

function requireAuth(req, res, next) {
  const token = req.cookies?.session;
  if (!token) return res.status(401).json({ error: 'auth required' });
  const s = db.prepare('SELECT phone FROM sessions WHERE token=?').get(token);
  if (!s) return res.status(401).json({ error: 'invalid session' });
  const u = db.prepare('SELECT is_banned FROM users WHERE phone=?').get(s.phone);
  if (u?.is_banned) return res.status(403).json({ error: 'number suspended' });
  req.user = { phone: s.phone };
  next();
}

// ---------- Facility info ----------
app.get('/api/facility/info', (req, res) => {
  const row = db
    .prepare('SELECT facility_phone, support_phone FROM facility_info WHERE id=1')
    .get();
  res.json(row || {});
});

app.post('/api/facility/info', requireAuth, (req, res) => {
  const { facility_phone, support_phone } = req.body || {};
  db.prepare(
    'UPDATE facility_info SET facility_phone=?, support_phone=?, updated_at=CURRENT_TIMESTAMP WHERE id=1'
  ).run(facility_phone, support_phone);
  res.json({ ok: true });
});

// ---------- Schedule builder ----------
app.post('/api/sites/:id/schedule', requireAuth /* optional: protect */, (req, res) => {
  try {
    const site_id = Number(req.params.id);
    const { date, open_time, close_time, loads_target, workins_per_hour = 0 } =
      req.body || {};
    if (!site_id || !date || !open_time || !close_time || !loads_target) {
      return res.status(400).json({ error: 'missing fields' });
    }

    // EAST(1)=5m, WEST(2)=6m
    const minInt = site_id === 2 ? 6 : 5;

    const start = minutes(open_time);
    const end = minutes(close_time);
    const dur = Math.max(0, end - start);

    let interval = 0;
    if (loads_target > 1)
      interval = Math.max(minInt, Math.floor(dur / (loads_target - 1)));

    const tx = db.transaction(() => {
      db.prepare(
        `INSERT INTO site_settings (site_id, date, loads_target, open_time, close_time, workins_per_hour)
         VALUES (?,?,?,?,?,?)
         ON CONFLICT(site_id, date) DO UPDATE SET
           loads_target=excluded.loads_target,
           open_time=excluded.open_time,
           close_time=excluded.close_time,
           workins_per_hour=excluded.workins_per_hour`
      ).run(site_id, date, loads_target, open_time, close_time, workins_per_hour);

      // create target slots
      const ins = db.prepare(
        'INSERT OR IGNORE INTO time_slots (site_id,date,slot_time,is_workin) VALUES (?,?,?,0)'
      );
      if (loads_target >= 1) {
        for (let i = 0; i < loads_target; i++) {
          const t = start + i * interval;
          if (t <= end) ins.run(site_id, date, hhmm(t));
        }
      }

      // optional work-ins (evenly spaced)
      if (workins_per_hour > 0) {
        const step = Math.floor(60 / workins_per_hour);
        for (let h = Math.floor(start / 60); h <= Math.floor(end / 60); h++) {
          for (let k = 0; k < workins_per_hour; k++) {
            const tm = h * 60 + k * step;
            if (tm >= start && tm <= end) {
              db.prepare(
                'INSERT OR IGNORE INTO time_slots (site_id,date,slot_time,is_workin) VALUES (?,?,?,1)'
              ).run(site_id, date, hhmm(tm));
            }
          }
        }
      }
    });
    tx();

    res.json({ ok: true, interval_min: interval });
  } catch (e) {
    console.error('/api/sites/:id/schedule', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- Open slots ----------
app.get('/api/sites/:id/slots', (req, res) => {
  expireHolds();
  const site_id = Number(req.params.id);
  const date = req.query?.date || todayLocalISO();
  if (!site_id) return res.status(400).json({ error: 'site_id required' });
  const rows = db
    .prepare(
      'SELECT slot_time FROM time_slots WHERE site_id=? AND date=? AND reserved_truck_id IS NULL AND hold_token IS NULL ORDER BY slot_time'
    )
    .all(site_id, date);
  res.json(rows.map((r) => r.slot_time));
});

// ---------- Hold / confirm / release ----------
app.post('/api/slots/hold', (req, res) => {
  expireHolds();
  const { site_id, date, slot_time } = req.body || {};
  if (!site_id || !date || !slot_time)
    return res.status(400).json({ error: 'missing params' });
  const row = db
    .prepare(
      'SELECT id, reserved_truck_id, hold_token, hold_expires_at FROM time_slots WHERE site_id=? AND date=? AND slot_time=?'
    )
    .get(site_id, date, slot_time);
  if (!row) return res.status(404).json({ error: 'slot not found' });
  if (row.reserved_truck_id) return res.status(409).json({ error: 'slot reserved' });
  if (row.hold_token && new Date(row.hold_expires_at) > new Date())
    return res.status(409).json({ error: 'slot on hold' });

  const token = crypto.randomUUID();
  db.prepare(
    "UPDATE time_slots SET hold_token=?, hold_expires_at=datetime('now','+120 seconds') WHERE id=?"
  ).run(token, row.id);
  const expires = db
    .prepare('SELECT hold_expires_at as e FROM time_slots WHERE id=?')
    .get(row.id).e;

  res.json({ hold_token: token, expires_at: expires });
});

app.post('/api/slots/confirm', async (req, res) => {
  expireHolds();
  const { hold_token } = req.body || {};
  if (!hold_token) return res.status(400).json({ error: 'hold_token required' });
  const slot = db
    .prepare(
      'SELECT * FROM time_slots WHERE hold_token=? AND hold_expires_at > CURRENT_TIMESTAMP'
    )
    .get(hold_token);
  if (!slot) return res.status(410).json({ error: 'hold expired or invalid' });

  const p = req.body || {};
  const manage_token = crypto.randomUUID();
  const ins = db.prepare(
    `INSERT INTO slot_reservations
    (site_id,date,slot_time,truck_id,license_plate,driver_name,driver_phone,vendor_name,farm_or_ticket,est_amount,est_unit,manage_token)
    VALUES (@site_id,@date,@slot_time,@truck_id,@license_plate,@driver_name,@driver_phone,@vendor_name,@farm_or_ticket,@est_amount,@est_unit,@manage_token)`
  );
  const info = ins.run({
    site_id: slot.site_id,
    date: slot.date,
    slot_time: slot.slot_time,
    truck_id: null,
    license_plate: p.license_plate || null,
    driver_name: p.driver_name || null,
    driver_phone: normalizePhone(p.driver_phone) || null,
    vendor_name: p.vendor_name || null,
    farm_or_ticket: p.farm_or_ticket || null,
    est_amount: p.est_amount || null,
    est_unit: (p.est_unit || 'BUSHELS').toUpperCase(),
    manage_token,
  });

  db.prepare(
    'UPDATE time_slots SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP, hold_token=NULL, hold_expires_at=NULL WHERE id=?'
  ).run(info.lastInsertRowid, slot.id);

  // Confirmation SMS (best-effort)
  const rrow = db
    .prepare('SELECT * FROM slot_reservations WHERE id=?')
    .get(info.lastInsertRowid);
  if (twilioClient && TWILIO_FROM && rrow?.driver_phone) {
    try {
      await twilioClient.messages.create({
        from: TWILIO_FROM,
        to: rrow.driver_phone,
        body: `Cargill: Confirmed ${rrow.date} at ${rrow.slot_time} (${rrow.site_id===1?'EAST':'WEST'}). Reply STOP to opt out.`,
      });
    } catch (e) {
      console.warn('Twilio confirm SMS error:', e?.message || e);
    }
  }

  res
    .status(201)
    .json({ ok: true, reservation_id: info.lastInsertRowid, manage_token, slot_time: slot.slot_time });
});

app.post('/api/slots/release', (req, res) => {
  const { hold_token } = req.body || {};
  if (!hold_token) return res.status(400).json({ error: 'hold_token required' });
  db.prepare(
    'UPDATE time_slots SET hold_token=NULL, hold_expires_at=NULL WHERE hold_token=?'
  ).run(hold_token);
  res.json({ ok: true });
});

// ---------- Reassign / cancel / mass-cancel ----------
app.post('/api/slots/reassign', requireAuth, (req, res) => {
  const { reservation_id, to_slot_time } = req.body || {};
  if (!reservation_id || !to_slot_time)
    return res.status(400).json({ error: 'missing fields' });
  const r = db.prepare('SELECT * FROM slot_reservations WHERE id=?').get(reservation_id);
  if (!r) return res.status(404).json({ error: 'reservation not found' });
  const target = db
    .prepare('SELECT * FROM time_slots WHERE site_id=? AND date=? AND slot_time=?')
    .get(r.site_id, r.date, to_slot_time);
  if (!target) return res.status(404).json({ error: 'target slot not found' });
  if (target.reserved_truck_id) return res.status(409).json({ error: 'target slot taken' });

  const tx = db.transaction(() => {
    db.prepare(
      'UPDATE time_slots SET reserved_truck_id=NULL, reserved_at=NULL WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?'
    ).run(r.site_id, r.date, r.slot_time, r.id);
    db.prepare('UPDATE time_slots SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP WHERE id=?').run(
      r.id,
      target.id
    );
    db.prepare('UPDATE slot_reservations SET slot_time=? WHERE id=?').run(to_slot_time, reservation_id);
  });
  tx();
  res.json({ ok: true });
});

app.post('/api/slots/cancel', requireAuth, async (req, res) => {
  const { reservation_id, reason } = req.body || {};
  if (!reservation_id) return res.status(400).json({ error: 'reservation_id required' });
  const r = db.prepare('SELECT * FROM slot_reservations WHERE id=?').get(reservation_id);
  if (!r) return res.status(404).json({ error: 'not found' });

  const tx = db.transaction(() => {
    db.prepare(
      'UPDATE time_slots SET reserved_truck_id=NULL, reserved_at=NULL WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?'
    ).run(r.site_id, r.date, r.slot_time, r.id);
    db.prepare('DELETE FROM slot_reservations WHERE id=?').run(reservation_id);
  });
  tx();

  // notify driver (best-effort)
  if (twilioClient && TWILIO_FROM && r?.driver_phone) {
    try {
      await twilioClient.messages.create({
        from: TWILIO_FROM,
        to: r.driver_phone,
        body: `Cargill: Your ${r.date} ${r.slot_time} (${r.site_id===1?'EAST':'WEST'}) was cancelled${reason?`: ${reason}`:''}.`,
      });
    } catch (e) {
      console.warn('Twilio cancel SMS error:', e?.message || e);
    }
  }

  res.json({ ok: true });
});

app.post('/api/slots/mass-cancel', requireAuth, async (req, res) => {
  const { site_id, date, reservation_ids = [], reason, notify = false } = req.body || {};
  if (!site_id || !date || !reservation_ids.length)
    return res.status(400).json({ error: 'missing fields' });

  const canceled = [];
  const phones = [];

  const tx = db.transaction(() => {
    for (const id of reservation_ids) {
      const r = db
        .prepare('SELECT * FROM slot_reservations WHERE id=? AND site_id=? AND date=?')
        .get(id, site_id, date);
      if (!r) continue;

      db.prepare(
        'UPDATE time_slots SET reserved_truck_id=NULL, reserved_at=NULL WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?'
      ).run(site_id, date, r.slot_time, r.id);
      db.prepare('DELETE FROM slot_reservations WHERE id=?').run(id);

      canceled.push(id);
      if (notify && r.driver_phone) phones.push(r.driver_phone);
    }
  });
  tx();

  // Notifications (best-effort)
  if (notify && twilioClient && TWILIO_FROM && phones.length) {
    const msg = `Cargill: Appointments on ${date} (${site_id===1?'EAST':'WEST'}) were cancelled${reason?`: ${reason}`:''}.`;
    for (const to of phones) {
      try { await twilioClient.messages.create({ from: TWILIO_FROM, to, body: msg }); }
      catch (e) { console.warn('Twilio mass-cancel SMS error:', e?.message || e); }
    }
  }

  res.json({ ok: true, canceled: canceled.length });
});

// ---------- Notify-only ----------
app.post('/api/slots/notify', requireAuth, async (req, res) => {
  const { reservation_id, message } = req.body || {};
  if (!reservation_id || !message)
    return res.status(400).json({ error: 'reservation_id and message required' });
  const r = db.prepare('SELECT driver_phone, date, slot_time, site_id FROM slot_reservations WHERE id=?').get(reservation_id);
  if (!r || !r.driver_phone) return res.status(404).json({ error: 'reservation/phone not found' });

  if (twilioClient && TWILIO_FROM) {
    try {
      const msg = await twilioClient.messages.create({
        from: TWILIO_FROM,
        to: r.driver_phone,
        body: `Cargill (${r.site_id===1?'EAST':'WEST'} ${r.date} ${r.slot_time}): ${message}`,
      });
      return res.json({ ok: true, sid: msg.sid, status: msg.status });
    } catch (e) {
      console.warn('Twilio notify error:', e?.message || e);
      return res.status(500).json({ error: 'twilio_error' });
    }
  } else {
    console.log(`[DEV] Notify to ${r.driver_phone}: ${message}`);
    return res.json({ ok: true, dev: true });
  }
});

// ---------- Scale verify ----------
app.get('/api/scale/verify', (req, res) => {
  const { code, site = 'EAST', date = todayLocalISO() } = req.query || {};
  if (!code || String(code).length !== 4)
    return res.status(400).json({ error: 'code must be 4 digits' });
  const sid = site === 'WEST' ? 2 : 1;
  const row = db
    .prepare(
      `SELECT id, queue_code, license_plate, driver_name, status, created_at, site_id
       FROM trucks
       WHERE queue_code = ? AND site_id = ? AND checkin_date = ?
       ORDER BY id DESC LIMIT 1`
    )
    .get(String(code), sid, date);
  if (!row) return res.status(404).json({ error: 'Not found for site/date' });
  res.json(row);
});

// ---------- Appointments list for facility ----------
app.get('/api/appointments', (req, res) => {
  const site_id = Number(req.query?.site_id);
  const date = req.query?.date || todayLocalISO();
  if (!site_id) return res.status(400).json({ error: 'site_id required' });
  const rows = db
    .prepare(
      'SELECT * FROM slot_reservations WHERE site_id=? AND date=? ORDER BY slot_time'
    )
    .all(site_id, date);
  res.json(rows);
});

// ---------- SPA fallback ----------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------- Start server ----------
const PORT = Number(getEnv('PORT', 10000));
app.listen(PORT, () => {
  console.log('Server running on http://localhost:' + PORT);
  console.log('CORS origin:', ORIGIN);
});
