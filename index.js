// index.js — Cargill Virtual Line (ESM) — SSE, interval override, driver-manage, OTP whitelists
import express from 'express';
import cookieParser from 'cookie-parser';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { EventEmitter } from 'events';

// ------------------------- Paths & ENV ---------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const PORT        = Number(process.env.PORT || 10000);
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const DB_PATH     = process.env.DB_PATH || 'data.db';

// Support both naming schemes for Render vs prior code
const TWILIO_SID  = process.env.TWILIO_ACCOUNT_SID || process.env.TWILIO_SID;
const TWILIO_AUTH = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_FROM = process.env.TWILIO_PHONE_NUMBER;

// Whitelists (comma-separated: +1XXXXXXXXXX)
function parseList(envVal) {
  return new Set(
    String(envVal || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  );
}
const ADMIN_WHITELIST = parseList(process.env.ADMIN_WHITELIST);
const PROBE_WHITELIST = parseList(process.env.PROBE_WHITELIST); // falls back to admin if empty later

const extraAllowed = ['+15636083369', '+15639205636'];
for (const num of extraAllowed) {
  ADMIN_WHITELIST.add(num);
  PROBE_WHITELIST.add(num)
}

// ------------------------- DB (idempotent schema) ----------------------------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
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
  date TEXT NOT NULL,        -- YYYY-MM-DD
  slot_time TEXT NOT NULL,   -- HH:MM
  is_workin INTEGER DEFAULT 0,
  reserved_truck_id INTEGER, -- reservation id
  reserved_at TEXT,
  hold_token TEXT,
  hold_expires_at TEXT,
  disabled INTEGER DEFAULT 0,
  UNIQUE(site_id, date, slot_time, is_workin)
);
CREATE TABLE IF NOT EXISTS slot_reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  slot_time TEXT NOT NULL,
  driver_name TEXT,
  license_plate TEXT,
  vendor_name TEXT,
  farm_or_ticket TEXT,
  est_amount REAL,
  est_unit TEXT,
  driver_phone TEXT,
  queue_code TEXT,               -- 4-digit probe/confirm code
  status TEXT DEFAULT 'reserved',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS otp_allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,           -- +1XXXXXXXXXX
  role  TEXT NOT NULL,           -- 'admin' or 'probe'
  added_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(phone, role)
);
CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations (site_id, date, queue_code);
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  code  TEXT NOT NULL,
  role  TEXT DEFAULT 'driver', -- 'driver' | 'admin' | 'probe'
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
`);

// --- One-time, idempotent column adders (for older DBs) ---
function tableHasColumn(table, col) {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all();
  return rows.some(r => r.name === col);
}
if (!tableHasColumn('time_slots','reserved_truck_id')) {
  db.exec(`ALTER TABLE time_slots ADD COLUMN reserved_truck_id INTEGER;`);
}
if (!tableHasColumn('time_slots','reserved_at')) {
  db.exec(`ALTER TABLE time_slots ADD COLUMN reserved_at TEXT;`);
}
if (!tableHasColumn('time_slots','disabled')) {
  db.exec(`ALTER TABLE time_slots ADD COLUMN disabled INTEGER DEFAULT 0;`);
}

// ------------------------- Twilio (optional) ---------------------------------
let twilio = null;
const hasTwilio = !!(TWILIO_SID && TWILIO_AUTH && TWILIO_FROM);
(async () => {
  try {
    if (hasTwilio) {
      const Twilio = (await import('twilio')).default;
      twilio = Twilio(TWILIO_SID, TWILIO_AUTH);
      console.log('Twilio: client initialized');
    } else {
      console.log('Twilio: not configured (using SMS mock)');
    }
  } catch (e) {
    console.warn('Twilio init failed, falling back to mock:', e?.message || e);
    twilio = null;
  }
})();
async function sendSMS(to, body) {
  try {
    if (!hasTwilio || !twilio) {
      console.log('[SMS MOCK]', to, body);
      return { sent: false, mock: true };
    }
    const msg = await twilio.messages.create({ from: TWILIO_FROM, to, body });
    return { sent: true, sid: msg.sid };
  } catch (e) {
    console.warn('Twilio error (non-fatal):', e?.message || e);
    return { sent: false, error: e?.message || 'twilio-failed' };
  }
}

// ------------------------- App & Middleware ----------------------------------
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// LIST allowlist (admin-only)
app.get('/api/admin/allowlist', requireAdmin, (req, res) => {
  const role = (String(req.query.role || 'admin').toLowerCase() === 'probe') ? 'probe' : 'admin';
  const envSet = role === 'probe' ? (PROBE_WHITELIST.size ? PROBE_WHITELIST : PROBE_WHITELIST) : ADMIN_WHITELIST;

  const env = Array.from(role === 'probe'
    ? (PROBE_WHITELIST.size ? PROBE_WHITELIST : new Set()) // only show probe env if set
    : ADMIN_WHITELIST);

  const rows = db.prepare(
    `SELECT phone, added_at FROM otp_allowlist WHERE role=? ORDER BY added_at DESC`
  ).all(role);

  res.json({ ok:true, role, env, db: rows });
});

// ADD to allowlist (admin-only)
app.post('/api/admin/allowlist', requireAdmin, (req, res) => {
  const role  = (String(req.body?.role || 'admin').toLowerCase() === 'probe') ? 'probe' : 'admin';
  const phone = normPhone(req.body?.phone);
  if (!phone) return res.status(400).json({ error: 'invalid phone' });
  try {
    db.prepare(
      `INSERT OR IGNORE INTO otp_allowlist (phone, role) VALUES (?, ?)`
    ).run(phone, role);
    return res.json({ ok:true });
  } catch (e) {
    console.error('/api/admin/allowlist POST', e);
    return res.status(500).json({ error:'server error' });
  }
});

// REMOVE from allowlist (admin-only)
app.delete('/api/admin/allowlist', requireAdmin, (req, res) => {
  const role  = (String(req.body?.role || 'admin').toLowerCase() === 'probe') ? 'probe' : 'admin';
  const phone = normPhone(req.body?.phone);
  if (!phone) return res.status(400).json({ error: 'invalid phone' });
  try {
    const info = db.prepare(
      `DELETE FROM otp_allowlist WHERE phone=? AND role=?`
    ).run(phone, role);
    return res.json({ ok:true, removed: info.changes });
  } catch (e) {
    console.error('/api/admin/allowlist DELETE', e);
    return res.status(500).json({ error:'server error' });
  }
});

// ------------------------- SSE bus -------------------------------------------
const bus = new EventEmitter();
bus.setMaxListeners(0);

function emitSlotsChanged(site_id, date) {
  bus.emit('slots-changed', { site_id, date, ts: Date.now() });
}

app.get('/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  const send = (evt, data) => {
    res.write(`event: ${evt}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };
  const handler = payload => send('slots-changed', payload);
  bus.on('slots-changed', handler);

  const ping = setInterval(() => send('ping', { ts: Date.now() }), 25000);

  req.on('close', () => {
    clearInterval(ping);
    bus.off('slots-changed', handler);
  });
});

// ------------------------- Helpers -------------------------------------------
const sixDigit = () => String(Math.floor(100000 + Math.random()*900000));
const fourDigit = () => String(Math.floor(1000 + Math.random()*9000));
const normPhone = p => {
  const d = String(p||'').replace(/\D/g,'');
  if (/^\d{10}$/.test(d)) return '+1'+d;
  if (/^1\d{10}$/.test(d))  return '+'+d;
  if (/^\+1\d{10}$/.test(d)) return d;
  return null;
};
const toMin  = hhmm => { const [h,m]=String(hhmm).split(':').map(n=>+n); return h*60+m; };
const toHHMM = mins => `${String(Math.floor(mins/60)).padStart(2,'0')}:${String(mins%60).padStart(2,'0')}`;
const todayISO = () => new Date().toISOString().slice(0,10);
function expireHolds() {
  db.prepare(`
    UPDATE time_slots
    SET hold_token=NULL, hold_expires_at=NULL
    WHERE hold_expires_at IS NOT NULL AND hold_expires_at < CURRENT_TIMESTAMP
  `).run();
}
function requireAdmin(req, res, next) {
  const phone = String(req.cookies?.session_phone || '');
  const role  = String(req.cookies?.session_role  || '');
  if (role !== 'admin') return res.status(403).json({ error: 'admin required' });

  // accept if in ENV whitelist or DB allowlist
  if (ADMIN_WHITELIST.has(phone)) return next();
  const inDb = db.prepare(`SELECT 1 FROM otp_allowlist WHERE phone=? AND role='admin'`).get(phone);
  if (inDb) return next();

  return res.status(403).json({ error: 'admin not allowlisted' });
}

// ------------------------- OTP Auth (with whitelists) ------------------------
function isWhitelisted(role, phone) {
  if (role === 'admin') {
    if (ADMIN_WHITELIST.has(phone)) return true;
    const row = db.prepare(`SELECT 1 FROM otp_allowlist WHERE phone=? AND role='admin'`).get(phone);
    return !!row;
  }
  if (role === 'probe') {
    // Probe: use PROBE list if present, otherwise fall back to admin list
    const envOk = (PROBE_WHITELIST.size ? PROBE_WHITELIST : ADMIN_WHITELIST).has(phone);
    if (envOk) return true;
    const row = db.prepare(`SELECT 1 FROM otp_allowlist WHERE phone=? AND role='probe'`).get(phone)
            || db.prepare(`SELECT 1 FROM otp_allowlist WHERE phone=? AND role='admin'`).get(phone);
    return !!row;
  }
  return true; // drivers are open
}

app.post('/auth/request-code', async (req, res) => {
  try {
    const phone = normPhone(req.body?.phone);
    const roleRaw = String(req.body?.role || 'driver').toLowerCase();
    const role  = (roleRaw === 'admin' || roleRaw === 'probe') ? roleRaw : 'driver';
    if (!phone) return res.status(400).json({ error:'invalid phone' });

    if (!isWhitelisted(role, phone)) {
      return res.status(403).json({ error: 'phone not authorized for this login' });
    }

    const code = sixDigit();
    db.prepare(`
      INSERT INTO otp_codes (phone, code, role, expires_at)
      VALUES (?, ?, ?, datetime('now','+10 minutes'))
    `).run(phone, code, role);

    const msg =
      role==='admin' ? `Cargill Admin Code: ${code}. Expires in 10 minutes.` :
      role==='probe' ? `Cargill Probe Portal Code: ${code}. Expires in 10 minutes.` :
      `Cargill Sign-in Code: ${code}. Expires in 10 minutes. Reply STOP to opt out.`;

    const sms = await sendSMS(phone, msg);
    return res.json({ ok:true, sms });
  } catch (e) {
    console.error('/auth/request-code', e);
    return res.json({ ok: true, sms: { sent:false, error:'server-caught' } });
  }
});

app.post('/auth/verify', (req, res) => {
  try {
    const phone = normPhone(req.body?.phone);
    const code  = String(req.body?.code || '');
    const roleRaw = String(req.body?.role || 'driver').toLowerCase();
    const role  = (roleRaw === 'admin' || roleRaw === 'probe') ? roleRaw : 'driver';

    if (!phone || !/^\d{6}$/.test(code)) return res.status(400).json({ error:'invalid' });
    if (!isWhitelisted(role, phone)) {
      return res.status(403).json({ error: 'phone not authorized for this login' });
    }

    const row = db.prepare(`
      SELECT * FROM otp_codes
      WHERE phone=? AND code=? AND role=? AND consumed_at IS NULL
        AND datetime(expires_at) > datetime('now')
      ORDER BY id DESC LIMIT 1
    `).get(phone, code, role);

    if (!row) return res.status(400).json({ error:'code invalid or expired' });

    db.prepare(`UPDATE otp_codes SET consumed_at=CURRENT_TIMESTAMP WHERE id=?`).run(row.id);
    res.cookie('session_phone', phone, { httpOnly:false, sameSite:'lax' });
    res.cookie('session_role' , role , { httpOnly:false, sameSite:'lax' });
    res.json({ ok:true });
  } catch (e) {
    console.error('/auth/verify', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Schedule PREVIEW (Generate Slots) -----------------
// Body: { date, open_time, close_time, loads_target, disabled_loads?, disabled_slots?, interval_min? }
app.post('/api/sites/:id/slots/preview', (req, res) => {
  try {
    const site_id = +req.params.id;
    const {
      date, open_time, close_time, loads_target,
      disabled_loads, disabled_slots, interval_min
    } = req.body || {};

    if (!site_id || !date || !open_time || !close_time || !loads_target) {
      return res.status(400).json({ error:'missing fields' });
    }

    const minInt = site_id === 2 ? 6 : 5;
    const start  = toMin(open_time);
    const end    = toMin(close_time);
    if (!(end > start)) return res.status(400).json({ error: 'close must be after open' });

    const span        = end - start;
    const wantedInt   = Math.max(0, Number(interval_min) || 0);
    const computedInt = Math.floor(span / Math.max(1, loads_target - 1));
    const interval    = Math.max(minInt, wantedInt > 0 ? wantedInt : computedInt);

    const times = [];
    for (let i = 0; i < loads_target; i++) {
      const t = start + i*interval;
      if (t >= start && t <= end) times.push(toHHMM(t));
    }

    const wantDisabled = Math.max(0, Number(disabled_loads ?? disabled_slots) || 0);
    const disabledSet = new Set();
    if (wantDisabled > 0 && times.length > 0) {
      const stride = Math.max(1, Math.round(times.length / wantDisabled));
      for (let i = stride - 1; i < times.length && disabledSet.size < wantDisabled; i += stride) {
        disabledSet.add(times[i]);
      }
      for (let i = times.length - 1; disabledSet.size < wantDisabled && i >= 0; i--) {
        if (!disabledSet.has(times[i])) disabledSet.add(times[i]);
      }
    }

    const items = times.map(t => ({ slot_time: t, disabled: disabledSet.has(t) ? 1 : 0 }));
    res.json({ ok:true, interval_min: interval, items });
  } catch (e) {
    console.error('/api/sites/:id/slots/preview', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Schedule PUBLISH (overwrite open) -----------------
// Body: { date, open_time, close_time, loads_target, disabled_loads, interval_min? }
app.post('/api/sites/:id/schedule', (req, res) => {
  const DEBUG = process.env.NODE_ENV !== 'production';

  try {
    const site_id = Number(req.params.id);
    let { date, open_time = '', close_time = '', loads_target,
          disabled_loads = 0, interval_min } = req.body || {};

    // normalize & validate
    date = String(date || '').trim();
    open_time = String(open_time || '').trim();
    close_time = String(close_time || '').trim();
    loads_target = Number(loads_target);
    disabled_loads = Math.max(0, Number(disabled_loads) || 0);
    const wantedInt = Math.max(0, Number(interval_min) || 0);

    const hhmmRe = /^(?:[01]\d|2[0-3]):[0-5]\d$/;
    if (!site_id || !date || !open_time || !close_time || !loads_target) {
      return res.status(400).json({ error: 'missing fields' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
    }
    if (!hhmmRe.test(open_time) || !hhmmRe.test(close_time)) {
      return res.status(400).json({ error: 'open/close must be HH:MM' });
    }
    if (!Number.isFinite(loads_target) || loads_target < 1) {
      return res.status(400).json({ error: 'loads_target must be >= 1' });
    }

    const minInt = site_id === 2 ? 6 : 5;
    const start  = toMin(open_time);
    const end    = toMin(close_time);
    if (!(end > start)) return res.status(400).json({ error: 'close must be after open' });

    const span        = end - start;
    const computedInt = Math.floor(span / Math.max(1, loads_target - 1));
    const interval    = Math.max(minInt, wantedInt > 0 ? wantedInt : computedInt);

    const times = [];
    for (let i = 0; i < loads_target; i++) {
      const t = start + i * interval;
      if (t >= start && t <= end) times.push(toHHMM(t));
    }

    const disabledSet = new Set();
    if (disabled_loads > 0 && times.length > 0) {
      const stride = Math.max(1, Math.round(times.length / disabled_loads));
      for (let i = stride - 1; i < times.length && disabledSet.size < disabled_loads; i += stride) {
        disabledSet.add(times[i]);
      }
      for (let i = times.length - 1; disabledSet.size < disabled_loads && i >= 0; i--) {
        if (!disabledSet.has(times[i])) disabledSet.add(times[i]);
      }
    }

    const tx = db.transaction(() => {
      db.prepare(`
        INSERT INTO site_settings (site_id, date, loads_target, open_time, close_time, workins_per_hour)
        VALUES (?, ?, ?, ?, ?, 0)
        ON CONFLICT(site_id, date) DO UPDATE SET
          loads_target     = excluded.loads_target,
          open_time        = excluded.open_time,
          close_time       = excluded.close_time,
          workins_per_hour = 0,
          updated_at       = CURRENT_TIMESTAMP
      `).run(site_id, date, loads_target, open_time, close_time);

      db.prepare(`
        DELETE FROM time_slots
        WHERE site_id = ? AND date = ? AND (reserved_truck_id IS NULL OR reserved_truck_id = 0)
      `).run(site_id, date);

      db.prepare(`
        UPDATE time_slots
           SET hold_token = NULL, hold_expires_at = NULL
         WHERE site_id = ? AND date = ?
      `).run(site_id, date);

      const ins = db.prepare(`
        INSERT INTO time_slots (site_id, date, slot_time, is_workin, reserved_truck_id, reserved_at, hold_token, hold_expires_at, disabled)
        VALUES (?, ?, ?, 0, NULL, NULL, NULL, NULL, ?)
        ON CONFLICT(site_id, date, slot_time, is_workin) DO UPDATE SET
          disabled = excluded.disabled
      `);
      for (const t of times) ins.run(site_id, date, t, disabledSet.has(t) ? 1 : 0);
    });
    tx();

    emitSlotsChanged(site_id, date);

    return res.json({
      ok: true,
      interval_min: interval,
      generated: times.length,
      disabled_count: disabledSet.size
    });
  } catch (e) {
    console.error('/api/sites/:id/schedule', e);
    return res.status(500).json({ error: 'server error' });
  }
});

// ------------------------- Facility Appointments (all slots) -----------------
app.get('/api/appointments', (req, res) => {
  try {
    const site_id = parseInt(req.query.site_id, 10);
    const date    = String(req.query.date || todayISO());
    if (!site_id) return res.status(400).json({ error:'site_id required' });

    const rows = db.prepare(`
      SELECT
        s.slot_time,
        s.is_workin,
        s.disabled,
        r.id               AS reservation_id,
        r.driver_name,
        r.license_plate,
        r.vendor_name,
        r.farm_or_ticket,
        r.est_amount,
        r.est_unit,
        r.driver_phone,
        r.queue_code,
        COALESCE(r.status, 'open') AS status
      FROM time_slots s
      LEFT JOIN slot_reservations r
        ON r.site_id=s.site_id AND r.date=s.date AND r.slot_time=s.slot_time
      WHERE s.site_id=? AND s.date=?
      ORDER BY time(s.slot_time)
    `).all(site_id, date);

    res.json({ ok:true, site_id, date, items: rows });
  } catch (e) {
    console.error('/api/appointments', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Driver (open) Slots -------------------------------
app.get('/api/sites/:id/slots', (req, res) => {
  try {
    expireHolds();
    const site_id = +req.params.id;
    const date    = String(req.query.date || todayISO());
    if (!site_id) return res.status(400).json({ error: 'site_id required' });

    const rows = db.prepare(`
      SELECT s.slot_time
      FROM time_slots s
      LEFT JOIN slot_reservations r
        ON r.site_id = s.site_id
       AND r.date    = s.date
       AND r.slot_time = s.slot_time
      WHERE s.site_id = ?
        AND s.date    = ?
        AND (s.disabled IS NULL OR s.disabled = 0)
        AND r.id IS NULL
        AND s.hold_token IS NULL
      ORDER BY time(s.slot_time)
    `).all(site_id, date);

    res.json(rows.map(r => r.slot_time));
  } catch (e) {
    console.error('/api/sites/:id/slots', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ------------------------- Hold / Confirm ------------------------------------
app.post('/api/slots/hold', (req, res) => {
  expireHolds();
  const { site_id, date, slot_time } = req.body || {};
  if (!site_id || !date || !slot_time) return res.status(400).json({ error:'missing fields' });

  const row = db.prepare(`
    SELECT id, reserved_truck_id, hold_expires_at, disabled
    FROM time_slots WHERE site_id=? AND date=? AND slot_time=?
  `).get(site_id, date, slot_time);

  if (!row) return res.status(404).json({ error:'slot not found' });
  if (row.disabled) return res.status(409).json({ error:'slot disabled' });
  if (row.reserved_truck_id) return res.status(409).json({ error:'slot reserved' });
  if (row.hold_expires_at && new Date(row.hold_expires_at) > new Date())
    return res.status(409).json({ error:'slot on hold' });

  const token = crypto.randomUUID();
  db.prepare(`
    UPDATE time_slots
    SET hold_token=?, hold_expires_at=datetime('now','+120 seconds')
    WHERE id=?
  `).run(token, row.id);

  const ex = db.prepare(`SELECT hold_expires_at AS e FROM time_slots WHERE id=?`).get(row.id).e;
  res.json({ hold_token: token, expires_at: ex });
});

app.post('/api/slots/confirm', async (req, res) => {
  expireHolds();
  const { hold_token } = req.body || {};
  if (!hold_token) return res.status(400).json({ error:'hold_token required' });

  const slot = db.prepare(`
    SELECT * FROM time_slots
    WHERE hold_token=? AND hold_expires_at > CURRENT_TIMESTAMP
  `).get(hold_token);
  if (!slot) return res.status(410).json({ error:'hold expired or invalid' });

  const {
    driver_name, license_plate, vendor_name,
    farm_or_ticket, est_amount, est_unit, driver_phone
  } = req.body || {};

  const probe = fourDigit();

  const info = db.prepare(`
    INSERT INTO slot_reservations
      (site_id,date,slot_time,driver_name,license_plate,vendor_name,
       farm_or_ticket,est_amount,est_unit,driver_phone,queue_code,status)
    VALUES (?,?,?,?,?,?,?,?,?,?,?, 'reserved')
    RETURNING id
  `).get(
    slot.site_id, slot.date, slot.slot_time,
    driver_name || null, license_plate || null, vendor_name || null,
    farm_or_ticket || null, est_amount || null, (est_unit || 'BUSHELS').toUpperCase(),
    normPhone(driver_phone) || null, probe
  );

  db.prepare(`
    UPDATE time_slots
    SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP,
        hold_token=NULL, hold_expires_at=NULL
    WHERE id=?
  `).run(info.id, slot.id);

  emitSlotsChanged(slot.site_id, slot.date);

  if (driver_phone) {
    await sendSMS(
      driver_phone,
      `Cargill: Confirmed ${slot.date} at ${slot.slot_time}. Probe code: ${probe}. Reply STOP to opt out.`
    );
  }

  res.status(201).json({ ok:true, reservation_id: info.id, queue_code: probe });
});

// ------------------- Probe Upsert (create or edit reservation) -------------------
app.post('/api/slots/probe-upsert', async (req, res) => {
  try {
    const {
      site_id, date, slot_time, reservation_id,
      driver_name, license_plate, vendor_name,
      farm_or_ticket, est_amount, est_unit,
      driver_phone, notify = false, reason = ''
    } = req.body || {};

    if (!site_id || !date || !slot_time) {
      return res.status(400).json({ error: 'site_id, date, slot_time required' });
    }

    const phoneNorm = normPhone(driver_phone);

    const slot = db.prepare(`
      SELECT * FROM time_slots
      WHERE site_id=? AND date=? AND slot_time=?
    `).get(site_id, date, slot_time);

    if (!slot) return res.status(404).json({ error: 'slot not found' });

    const newProbeCode = () => String(Math.floor(1000 + Math.random()*9000));

    let created = false;
    let updated = false;
    let queue_code = null;
    let resvId = reservation_id || null;

    const tx = db.transaction(() => {
      if (reservation_id) {
        const prev = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
        if (!prev) throw new Error('reservation not found');

        db.prepare(`
          UPDATE slot_reservations SET
            driver_name = ?, license_plate = ?, vendor_name = ?,
            farm_or_ticket = ?, est_amount = ?, est_unit = ?,
            driver_phone = ?
          WHERE id = ?
        `).run(
          driver_name || null,
          license_plate || null,
          vendor_name || null,
          farm_or_ticket || null,
          est_amount ?? null,
          (est_unit || 'BUSHELS').toUpperCase(),
          phoneNorm || null,
          reservation_id
        );

        queue_code = prev.queue_code || null;
        updated = true;

        db.prepare(`
          UPDATE time_slots
             SET reserved_truck_id = ?
           WHERE site_id=? AND date=? AND slot_time=? 
        `).run(reservation_id, site_id, date, slot_time);
      } else {
        if (slot.reserved_truck_id) throw new Error('slot already reserved');
        const code = newProbeCode();

        const info = db.prepare(`
          INSERT INTO slot_reservations
            (site_id, date, slot_time, driver_name, license_plate, vendor_name,
             farm_or_ticket, est_amount, est_unit, driver_phone, queue_code, status)
          VALUES (?,?,?,?,?,?,?,?,?,?,?, 'reserved')
          RETURNING id
        `).get(
          site_id, date, slot_time,
          driver_name || null,
          license_plate || null,
          vendor_name || null,
          farm_or_ticket || null,
          est_amount ?? null,
          (est_unit || 'BUSHELS').toUpperCase(),
          phoneNorm || null,
          code
        );

        db.prepare(`
          UPDATE time_slots
             SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP,
                 hold_token=NULL, hold_expires_at=NULL
           WHERE id=?
        `).run(info.id, slot.id);

        resvId = info.id;
        queue_code = code;
        created = true;
      }
    });
    tx();

    emitSlotsChanged(site_id, date);

    if (notify && phoneNorm) {
      try {
        if (created) {
          const body =
            `Cargill: Confirmed ${date} at ${slot_time} (${site_id===1?'EAST':'WEST'}). ` +
            `Probe code: ${queue_code}. Reply STOP to opt out.`;
          await sendSMS(phoneNorm, body);
        } else if (updated) {
          const body =
            `Cargill: Your ${date} ${slot_time} (${site_id===1?'EAST':'WEST'}) details were updated${reason?`: ${reason}`:''}.` +
            (queue_code ? ` Probe code: ${queue_code}.` : '');
          await sendSMS(phoneNorm, body);
        }
      } catch {}
    }

    return res.json({ ok: true, reservation_id: resvId, created, updated, queue_code });
  } catch (e) {
    console.error('probe-upsert', e);
    return res.status(500).json({ error: 'server error' });
  }
});

// ------------------------- Cancel / Reassign ---------------------------------
app.post('/api/slots/cancel', (req, res) => {
  const { reservation_id } = req.body || {};
  if (!reservation_id) return res.status(400).json({ error:'reservation_id required' });

  const r = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
  if (!r) return res.status(404).json({ error:'not found' });

  db.prepare(`DELETE FROM slot_reservations WHERE id=?`).run(reservation_id);
  db.prepare(`
    UPDATE time_slots
    SET reserved_truck_id=NULL, reserved_at=NULL
    WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?
  `).run(r.site_id, r.date, r.slot_time, r.id);

  emitSlotsChanged(r.site_id, r.date);

  res.json({ ok:true, reservation_id, queue_code: r.queue_code });
});

app.post('/api/slots/reassign', (req, res) => {
  const { reservation_id, to_slot_time } = req.body || {};
  if (!reservation_id || !to_slot_time) return res.status(400).json({ error:'missing fields' });

  const r = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
  if (!r) return res.status(404).json({ error:'not found' });

  db.prepare(`
    INSERT OR IGNORE INTO time_slots (site_id, date, slot_time, is_workin)
    VALUES (?, ?, ?, 0)
  `).run(r.site_id, r.date, to_slot_time);

  const tgt = db.prepare(`
    SELECT * FROM time_slots WHERE site_id=? AND date=? AND slot_time=?
  `).get(r.site_id, r.date, to_slot_time);
  if (tgt.reserved_truck_id) return res.status(409).json({ error:'target slot reserved' });

  const tx = db.transaction(() => {
    db.prepare(`
      UPDATE time_slots
      SET reserved_truck_id=NULL, reserved_at=NULL
      WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?
    `).run(r.site_id, r.date, r.slot_time, r.id);

    db.prepare(`
      UPDATE time_slots
      SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP
      WHERE id=?
    `).run(r.id, tgt.id);

    db.prepare(`UPDATE slot_reservations SET slot_time=? WHERE id=?`)
      .run(to_slot_time, reservation_id);
  });
  tx();

  emitSlotsChanged(r.site_id, r.date);

  res.json({ ok:true, reservation_id, to_slot_time, queue_code: r.queue_code });
});

// ------------------------- Admin: reserve/update (for completeness) ----------
app.post('/api/admin/reserve', async (req, res) => {
  try {
    // (optional) could check session_role === 'admin' here if you wire cookie-based gating on the UI
    const { site_id, date, slot_time, driver_name, driver_phone,
            license_plate, vendor_name, farm_or_ticket,
            est_amount, est_unit, queue_code } = req.body || {};
    if (!site_id || !date || !slot_time) {
      return res.status(400).json({ error:'site_id, date, slot_time required' });
    }

    const probe = queue_code || String(Math.floor(1000 + Math.random()*9000));

    const info = db.prepare(`
      INSERT INTO slot_reservations
        (site_id,date,slot_time,driver_name,license_plate,vendor_name,
         farm_or_ticket,est_amount,est_unit,driver_phone,queue_code,status)
      VALUES (?,?,?,?,?,?,?,?,?,?,?, 'reserved')
      RETURNING id
    `).get(site_id, date, slot_time,
           driver_name||null, license_plate||null, vendor_name||null,
           farm_or_ticket||null, est_amount||null, (est_unit||'BUSHELS').toUpperCase(),
           normPhone(driver_phone)||null, probe);

    db.prepare(`
      UPDATE time_slots
         SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP
       WHERE site_id=? AND date=? AND slot_time=?
    `).run(info.id, site_id, date, slot_time);

    emitSlotsChanged(site_id, date);

    if (driver_phone) {
      const msg = `Cargill: Reserved ${date} at ${slot_time}. Probe code: ${probe}. Reply STOP to opt out.`;
      await sendSMS(driver_phone, msg);
    }

    res.json({ ok:true, reservation_id: info.id, queue_code: probe });
  } catch (e) {
    console.error('admin-reserve', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/admin/update-reservation', async (req, res) => {
  try {
    const { reservation_id, driver_name, driver_phone, license_plate,
            vendor_name, farm_or_ticket, est_amount, est_unit } = req.body || {};
    if (!reservation_id) return res.status(400).json({ error:'reservation_id required' });

    const row = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
    if (!row) return res.status(404).json({ error:'reservation not found' });

    db.prepare(`
      UPDATE slot_reservations
         SET driver_name=?, driver_phone=?, license_plate=?,
             vendor_name=?, farm_or_ticket=?, est_amount=?, est_unit=?
       WHERE id=?
    `).run(driver_name, normPhone(driver_phone), license_plate,
           vendor_name, farm_or_ticket, est_amount, (est_unit||'BUSHELS').toUpperCase(), reservation_id);

    if (driver_phone) {
      const msg = `Cargill: Your ${row.date} ${row.slot_time} reservation has been updated. Probe code: ${row.queue_code||'N/A'}.`;
      await sendSMS(driver_phone, msg);
    }

    res.json({ ok:true });
  } catch (e) {
    console.error('update-reservation', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Enable / Disable Open Slots -----------------------
app.post('/api/slots/disable', (req, res) => {
  try {
    const { site_id, date, slot_times = [] } = req.body || {};
    if (!site_id || !date || !Array.isArray(slot_times) || slot_times.length === 0) {
      return res.status(400).json({ ok:false, error: 'site_id, date, slot_times[] required' });
    }
    const q = slot_times.map(() => '?').join(',');
    const info = db.prepare(`
      UPDATE time_slots
         SET disabled = 1
       WHERE site_id = ? AND date = ? AND slot_time IN (${q})
    `).run(site_id, date, ...slot_times);

    if (info.changes) emitSlotsChanged(site_id, date);
    return res.json({ ok:true, updated: info.changes });
  } catch (e) {
    console.error('/api/slots/disable', e);
    return res.status(500).json({ ok:false, error: 'server error' });
  }
});

app.post('/api/slots/enable', (req, res) => {
  try {
    const { site_id, date, slot_times = [] } = req.body || {};
    if (!site_id || !date || !Array.isArray(slot_times) || slot_times.length === 0) {
      return res.status(400).json({ ok:false, error: 'site_id, date, slot_times[] required' });
    }
    const q = slot_times.map(() => '?').join(',');
    const info = db.prepare(`
      UPDATE time_slots
         SET disabled = 0
       WHERE site_id = ? AND date = ? AND slot_time IN (${q})
    `).run(site_id, date, ...slot_times);

    if (info.changes) emitSlotsChanged(site_id, date);
    return res.json({ ok:true, updated: info.changes });
  } catch (e) {
    console.error('/api/slots/enable', e);
    return res.status(500).json({ ok:false, error: 'server error' });
  }
});

// ------------------------- Mass Cancel / Notify / Disable-Enable -------------
app.post('/api/slots/mass-cancel', async (req, res) => {
  try {
    const { site_id, date, reservation_ids = [], slot_times = [], notify = false, reason = '' } = req.body || {};
    if (!site_id || !date) return res.status(400).json({ error: 'site_id and date required' });

    const getResById = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`);
    const freeSlot   = db.prepare(`
      UPDATE time_slots
         SET reserved_truck_id=NULL, reserved_at=NULL
       WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?`);
    const delRes     = db.prepare(`DELETE FROM slot_reservations WHERE id=?`);
    const delOpen    = db.prepare(`
      DELETE FROM time_slots
       WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id IS NULL
    `);

    const affectedReservations = [];
    const removedOpenSlots     = [];
    const phones = [];

    const tx = db.transaction(() => {
      for (const id of (Array.isArray(reservation_ids)?reservation_ids:[])) {
        if (!Number.isInteger(id)) continue;
        const r = getResById.get(id);
        if (!r) continue;
        freeSlot.run(r.site_id, r.date, r.slot_time, r.id);
        delRes.run(id);
        affectedReservations.push({ id, site_id: r.site_id, date: r.date, slot_time: r.slot_time, driver_phone: r.driver_phone || null });
        if (notify && r.driver_phone) phones.push(r.driver_phone);
      }

      if (Array.isArray(slot_times) && slot_times.length) {
        for (const t of slot_times) {
          const info = delOpen.run(site_id, date, t);
          if (info.changes > 0) removedOpenSlots.push({ site_id, date, slot_time: t });
        }
      }
    });
    tx();

    if (affectedReservations.length || removedOpenSlots.length) emitSlotsChanged(site_id, date);

    let notified = 0;
    if (notify && phones.length) {
      const msg = `Cargill: Appointment${phones.length>1?'s':''} on ${date} (${site_id===1?'EAST':'WEST'}) cancelled${reason?`: ${reason}`:''}.`;
      for (const to of phones) {
        try { const s = await sendSMS(to, msg); if (s.sent) notified++; } catch (_) {}
      }
    }

    return res.json({
      ok: true,
      canceled: affectedReservations.length,
      removed_open: removedOpenSlots.length,
      notified,
      details: { reservations: affectedReservations, open_slots: removedOpenSlots }
    });
  } catch (e) {
    console.error('SQL error in /api/slots/mass-cancel:', e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/slots/mass-notify', async (req, res) => {
  try {
    const { site_id, date, reservation_ids = [], message } = req.body || {};
    if (!site_id || !date || !Array.isArray(reservation_ids) || !reservation_ids.length || !message) {
      return res.status(400).json({ error: 'site_id, date, reservation_ids, message required' });
    }
    const qMarks = reservation_ids.map(() => '?').join(',');
    const rows = db.prepare(`
      SELECT driver_phone
        FROM slot_reservations
       WHERE site_id=? AND date=? AND id IN (${qMarks})
         AND driver_phone IS NOT NULL
    `).all(site_id, date, ...reservation_ids);

    let sent = 0;
    for (const r of rows) {
      try { const s = await sendSMS(r.driver_phone, message); if (s.sent) sent++; } catch (_) {}
    }
    return res.json({ ok: true, targeted: rows.length, sent });
  } catch (e) {
    console.error('SQL error in /api/slots/mass-notify:', e);
    return res.status(500).json({ error: 'server error' });
  }
});

// ------------------------- Driver Manage (secure) ----------------------------
// Lookup by phone (full or last 4) + probe code
app.post('/api/driver/manage/lookup', (req, res) => {
  try {
    const probe = String(req.body?.probe_code || '').trim();
    const phoneRaw = String(req.body?.phone || '').trim();

    if (!/^\d{4}$/.test(probe)) {
      return res.status(400).json({ error: 'valid 4-digit probe_code required' });
    }

    // Helpful trace – shows exactly what the server received
    console.log('[lookup] raw phone:', phoneRaw, 'probe:', probe);

    let row;

    // If user typed exactly 4 digits, treat as "last 4" search
    if (/^\d{4}$/.test(phoneRaw)) {
      row = db.prepare(`
        SELECT id, site_id, date, slot_time, driver_name, license_plate, vendor_name,
               farm_or_ticket, est_amount, est_unit, driver_phone, queue_code, status
        FROM slot_reservations
        WHERE substr(driver_phone, -4) = ?
          AND queue_code = ?
        ORDER BY datetime(created_at) DESC
        LIMIT 1
      `).get(phoneRaw, probe);
    } else {
      // Try full normalization (+1XXXXXXXXXX)
      const phoneFull = normPhone(phoneRaw);
      if (!phoneFull) {
        return res.status(400).json({ error: 'enter 10-digit phone or last 4' });
      }
      row = db.prepare(`
        SELECT id, site_id, date, slot_time, driver_name, license_plate, vendor_name,
               farm_or_ticket, est_amount, est_unit, driver_phone, queue_code, status
        FROM slot_reservations
        WHERE driver_phone = ?
          AND queue_code = ?
        ORDER BY datetime(created_at) DESC
        LIMIT 1
      `).get(phoneFull, probe);
    }

    if (!row) return res.status(404).json({ error: 'no reservation found for that phone + code' });

    return res.json({ ok: true, reservation: row });
  } catch (e) {
    console.error('/api/driver/manage/lookup', e);
    res.status(500).json({ error: 'server error' });
  }
});

// Update fields (requires phone + probe_code to match reservation)
app.post('/api/driver/manage/update', async (req, res) => {
  try {
    const {
      reservation_id, phone, probe_code,
      driver_name, license_plate, vendor_name,
      farm_or_ticket, est_amount, est_unit
    } = req.body || {};

    if (!reservation_id) return res.status(400).json({ error: 'reservation_id required' });

    const phoneNorm = normPhone(phone);
    if (!phoneNorm || !/^\d{4}$/.test(String(probe_code||''))) {
      return res.status(400).json({ error: 'valid phone and 4-digit probe_code required' });
    }

    const row = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
    if (!row) return res.status(404).json({ error:'reservation not found' });

    // Security gate: both phone AND probe code must match this reservation
    if ((row.driver_phone || '') !== phoneNorm || (row.queue_code || '') !== String(probe_code)) {
      return res.status(403).json({ error: 'phone or probe code does not match this reservation' });
    }

    const setParts = [];
    const vals = [];
    const push = (col, val) => { setParts.push(`${col}=?`); vals.push(val); };

    if (driver_name !== undefined)   push('driver_name', driver_name || null);
    if (license_plate !== undefined) push('license_plate', license_plate || null);
    if (vendor_name !== undefined)   push('vendor_name', vendor_name || null);
    if (farm_or_ticket !== undefined)push('farm_or_ticket', farm_or_ticket || null);
    if (est_amount !== undefined)    push('est_amount', est_amount ?? null);
    if (est_unit !== undefined)      push('est_unit', (String(est_unit || 'BUSHELS')).toUpperCase());

    if (!setParts.length) return res.json({ ok: true, updated: 0 });

    const sql = `UPDATE slot_reservations SET ${setParts.join(', ')} WHERE id=?`;
    vals.push(reservation_id);
    const info = db.prepare(sql).run(...vals);

    // Optional courtesy SMS (no probe code included here)
    if (row.driver_phone) {
      try {
        await sendSMS(row.driver_phone, `Cargill: Your ${row.date} ${row.slot_time} reservation details were updated.`);
      } catch (_) {}
    }

    return res.json({ ok: true, updated: info.changes });
  } catch (e) {
    console.error('/api/driver/manage/update', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Debug --------------------------------------------
app.get('/healthz', (_req, res) => res.json({ ok:true }));
app.get('/debug/env', (_req, res) => {
  res.json({
    PORT, CORS_ORIGIN, DB_PATH,
    hasTwilio: !!(TWILIO_SID && TWILIO_AUTH && TWILIO_FROM),
    admin_whitelist: Array.from(ADMIN_WHITELIST),
    probe_whitelist: Array.from(PROBE_WHITELIST)
  });
});
app.get('/debug/slots', (req,res)=>{
  const { site_id=1, date=todayISO() } = req.query;
  const rows = db.prepare(`
    SELECT slot_time, is_workin, disabled, reserved_truck_id
    FROM time_slots WHERE site_id=? AND date=?
    ORDER BY time(slot_time)
  `).all(+site_id, String(date));
  res.json(rows);
});

// ------------------------- Append Times (no disruption) ----------------------
// Body: { site_id, date, start, end, loads_target?, interval_min?, is_workin? }
app.post('/api/slots/add-times', (req, res) => {
  try {
    const { site_id, date, start, end, loads_target, interval_min, is_workin = 0 } = req.body || {};

    if (!site_id || !date || !start || !end) {
      return res.status(400).json({ ok:false, error: 'site_id, date, start, end required' });
    }
    const hhmmRe = /^(?:[01]\d|2[0-3]):[0-5]\d$/;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date))) {
      return res.status(400).json({ ok:false, error: 'date must be YYYY-MM-DD' });
    }
    if (!hhmmRe.test(String(start)) || !hhmmRe.test(String(end))) {
      return res.status(400).json({ ok:false, error: 'start/end must be HH:MM' });
    }

    const s = toMin(start);
    const e = toMin(end);
    if (!(e >= s)) return res.status(400).json({ ok:false, error: 'end must be >= start' });

    const siteMin = (Number(site_id) === 2 ? 6 : 5);
    let step;
    if (Number(interval_min)) {
      step = Math.max(siteMin, Number(interval_min));
    } else {
      const lt = Number(loads_target);
      if (!lt || lt < 1) return res.status(400).json({ ok:false, error: 'loads_target >= 1 or interval_min required' });
      const span = Math.max(1, e - s);
      step = Math.max(siteMin, Math.floor(span / Math.max(1, lt - 1)));
    }

    const newTimes = [];
    for (let t = s; t <= e; t += step) newTimes.push(toHHMM(t));

    const ins = db.prepare(`
      INSERT INTO time_slots
        (site_id, date, slot_time, is_workin, reserved_truck_id, reserved_at, hold_token, hold_expires_at, disabled)
      VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, 0)
      ON CONFLICT(site_id, date, slot_time, is_workin) DO UPDATE SET
        disabled = 0
    `);

    const tx = db.transaction(() => {
      for (const t of newTimes) ins.run(site_id, date, t, is_workin ? 1 : 0);
    });
    tx();

    emitSlotsChanged(site_id, date);

    return res.json({ ok:true, inserted: newTimes.length, slot_times: newTimes });
  } catch (e) {
    console.error('/api/slots/add-times', e);
    return res.status(500).json({ ok:false, error:'server error' });
  }
});

// ------------------------- Start ---------------------------------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('CORS origin:', CORS_ORIGIN);
});
