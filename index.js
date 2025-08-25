// index.js — Cargill Virtual Line (ESM)
import 'dotenv/config';
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
  date TEXT NOT NULL,
  slot_time TEXT NOT NULL,
  is_workin INTEGER DEFAULT 0,
  reserved_truck_id INTEGER,
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
  queue_code TEXT,
  status TEXT DEFAULT 'reserved',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations (site_id, date, queue_code);
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  code  TEXT NOT NULL,
  role  TEXT DEFAULT 'driver',
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
`);

// ------------------------- Twilio (optional) ---------------------------------
let twilio = null;
const hasTwilio = !!(TWILIO_SID && TWILIO_AUTH && TWILIO_FROM);
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

// ------------------------- Allow Lists ---------------------------------------
const ADMIN_ALLOW = new Set([
  '+15636083369', // 563-608-3369
  '+15639205636', // 563-920-5636
]);
const PROBE_ALLOW = new Set([
  '+15636083369',
  '+15639205636',
]);

// ------------------------- App & Middleware ----------------------------------
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));

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

// ------------------------- OTP Auth ------------------------------------------
app.post('/auth/request-code', async (req, res) => {
  try {
    const phone = normPhone(req.body?.phone);
    const role  = req.body?.role === 'admin' ? 'admin' : (req.body?.role === 'probe' ? 'probe' : 'driver');
    if (!phone) return res.status(400).json({ error:'invalid phone' });

    // enforce allow-lists
    if (role === 'admin' && !ADMIN_ALLOW.has(phone)) {
      return res.status(403).json({ error:'not authorized for admin login' });
    }
    if (role === 'probe' && !PROBE_ALLOW.has(phone)) {
      return res.status(403).json({ error:'not authorized for probe login' });
    }

    const code = sixDigit();
    db.prepare(`
      INSERT INTO otp_codes (phone, code, role, expires_at)
      VALUES (?, ?, ?, datetime('now','+10 minutes'))
    `).run(phone, code, role);

    const sms = await sendSMS(
      phone,
      role==='admin'
        ? `Cargill Admin Code: ${code}. Expires in 10 minutes.`
        : role==='probe'
        ? `Cargill Probe Code: ${code}. Expires in 10 minutes.`
        : `Cargill Sign-in Code: ${code}. Expires in 10 minutes.`
    );

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
    const role  = req.body?.role === 'admin' ? 'admin' : (req.body?.role === 'probe' ? 'probe' : 'driver');
    if (!phone || !/^\d{6}$/.test(code)) return res.status(400).json({ error:'invalid' });

    // enforce allow-lists
    if (role === 'admin' && !ADMIN_ALLOW.has(phone)) {
      return res.status(403).json({ error:'not authorized for admin login' });
    }
    if (role === 'probe' && !PROBE_ALLOW.has(phone)) {
      return res.status(403).json({ error:'not authorized for probe login' });
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

// ... rest of your existing index.js unchanged (schedules, slots, reservations, etc.)

// ------------------------- Start ---------------------------------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('CORS origin:', CORS_ORIGIN);
});
