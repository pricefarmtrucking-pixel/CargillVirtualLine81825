// index.js — ESM
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import Database from 'better-sqlite3';
import twilioPkg from 'twilio';

const {
  PORT = 10000,
  CORS_ORIGIN = '*',
  DB_PATH = 'data.db',
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER
} = process.env;

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: true
}));
app.use(express.static('public'));

// ---- Twilio (optional) ------------------------------------------------------
const hasTwilio = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_PHONE_NUMBER;
const twilio = hasTwilio ? twilioPkg(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;

async function sendSMS(to, body) {
  if (!hasTwilio) {
    console.log('[SMS MOCK]', to, body);
    return { sid: 'mock', to, body, sent: false, error: 'twilio-not-configured' };
  }
  try {
    const msg = await twilio.messages.create({ from: TWILIO_PHONE_NUMBER, to, body });
    return { sid: msg.sid, to, body, sent: true };
  } catch (e) {
    console.error('Twilio error:', e?.message || e);
    return { sent: false, error: e?.message || 'twilio-failed' };
  }
}

// ---- Helpers ----------------------------------------------------------------
const sixDigit = () => String(Math.floor(100000 + Math.random()*900000));
const fourDigit = () => String(Math.floor(1000 + Math.random()*9000));

const normPhone = p => {
  const d = String(p||'').replace(/\D/g,'');
  if (/^\d{10}$/.test(d)) return '+1'+d;
  if (/^1\d{10}$/.test(d)) return '+'+d;
  if (/^\+1\d{10}$/.test(d)) return d;
  return null;
};

// ---- OTP tables (idempotent) -----------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS otp_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    code TEXT NOT NULL,
    role TEXT DEFAULT 'driver',
    expires_at TEXT NOT NULL,
    attempts_left INTEGER DEFAULT 5,
    consumed_at TEXT
  );
`);
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes (phone);
`);

// ---- AUTH: request code, verify ---------------------------------------------
app.post('/auth/request-code', async (req, res) => {
  try {
    const phone = normPhone(req.body?.phone);
    const role = req.body?.role === 'admin' ? 'admin' : 'driver';
    if (!phone) return res.status(400).json({ error: 'invalid phone' });

    const code = sixDigit();
    const expires = new Date(Date.now() + 10*60*1000).toISOString(); // 10 min
    db.prepare(`
      INSERT INTO otp_codes (phone, code, role, expires_at)
      VALUES (?,?,?,?)
    `).run(phone, code, role, expires);

    const sms = await sendSMS(phone,
      role === 'admin'
        ? `Cargill Admin Code: ${code}. Expires in 10 minutes.`
        : `Cargill Sign-in Code: ${code}. Expires in 10 minutes. Reply STOP to opt out.`
    );

    res.json({ ok: true, sms });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/auth/verify', (req, res) => {
  try {
    const phone = normPhone(req.body?.phone);
    const code  = String(req.body?.code || '');
    const role  = req.body?.role === 'admin' ? 'admin' : 'driver';
    if (!phone || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'invalid' });

    const row = db.prepare(`
      SELECT * FROM otp_codes
      WHERE phone=? AND code=? AND role=? AND consumed_at IS NULL
        AND datetime(expires_at) > datetime('now')
      ORDER BY id DESC LIMIT 1
    `).get(phone, code, role);

    if (!row) return res.status(400).json({ error: 'code invalid or expired' });

    if (row.attempts_left <= 0)
      return res.status(400).json({ error: 'too many attempts' });

    db.prepare(`UPDATE otp_codes SET consumed_at=CURRENT_TIMESTAMP WHERE id=?`).run(row.id);

    // For simplicity, set a signed-ish cookie (not cryptographically signed).
    res.cookie('session_phone', phone, { httpOnly: false, sameSite: 'lax' });
    res.cookie('session_role' , role , { httpOnly: false, sameSite: 'lax' });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Appointments API -------------------------------------------------------
// Returns EVERY slot for the site/date with reservation data if present.
// Query: ?site_id=<int>&date=YYYY-MM-DD
app.get('/api/appointments', (req, res) => {
  try {
    const site_id = parseInt(req.query.site_id, 10);
    const date = String(req.query.date || '').trim();
    if (!site_id || !date) return res.status(400).json({ error: 'site_id and date required' });

    const rows = db.prepare(`
      SELECT
        s.slot_time,
        r.id             AS reservation_id,
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
        ON r.site_id = s.site_id
       AND r.date    = s.date
       AND r.slot_time = s.slot_time
      WHERE s.site_id = ? AND s.date = ?
      ORDER BY time(s.slot_time)
    `).all(site_id, date);

    res.json({ ok: true, site_id, date, items: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Reserve (creates probe code + SMS) -------------------------------------
app.post('/api/slots/reserve', async (req, res) => {
  try {
    const {
      site_id, date, slot_time,
      driver_name, license_plate, vendor_name,
      farm_or_ticket, est_amount, est_unit, driver_phone
    } = req.body || {};

    if (!site_id || !date || !slot_time)
      return res.status(400).json({ error: 'site_id, date, slot_time required' });

    const code = fourDigit();

    // Upsert slot row so the left-join has it
    db.prepare(`
      INSERT OR IGNORE INTO time_slots (site_id, date, slot_time, is_workin)
      VALUES (?,?,?,0)
    `).run(site_id, date, slot_time);

    const info = db.prepare(`
      INSERT INTO slot_reservations
        (site_id, date, slot_time, driver_name, license_plate, vendor_name,
         farm_or_ticket, est_amount, est_unit, driver_phone, status, queue_code)
      VALUES (?,?,?,?,?,?,?,?,?,?, 'reserved', ?)
      RETURNING id
    `).get(
      site_id, date, slot_time, driver_name, license_plate, vendor_name,
      farm_or_ticket, est_amount, est_unit, driver_phone, code
    );

    // SMS confirm incl. 4-digit probe code
    if (driver_phone) {
      await sendSMS(driver_phone,
        `Cargill: Confirmed ${date} at ${slot_time}. Probe code: ${code}. Reply STOP to opt out.`
      );
    }

    res.json({ ok: true, reservation_id: info.id, queue_code: code });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Cancel (includes probe_code in response) --------------------------------
app.post('/api/slots/cancel', (req, res) => {
  try {
    const { reservation_id } = req.body || {};
    if (!reservation_id) return res.status(400).json({ error: 'reservation_id required' });

    const row = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
    if (!row) return res.status(404).json({ error: 'not found' });

    db.prepare(`UPDATE slot_reservations SET status='canceled' WHERE id=?`).run(reservation_id);

    res.json({ ok: true, reservation_id, queue_code: row.queue_code });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Reassign (includes probe_code in response) ------------------------------
app.post('/api/slots/reassign', (req, res) => {
  try {
    const { reservation_id, to_slot_time } = req.body || {};
    if (!reservation_id || !to_slot_time)
      return res.status(400).json({ error: 'reservation_id and to_slot_time required' });

    const row = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
    if (!row) return res.status(404).json({ error: 'not found' });

    // Ensure target slot exists
    db.prepare(`
      INSERT OR IGNORE INTO time_slots (site_id, date, slot_time, is_workin)
      VALUES (?,?,?,0)
    `).run(row.site_id, row.date, to_slot_time);

    db.prepare(`UPDATE slot_reservations SET slot_time=? WHERE id=?`)
      .run(to_slot_time, reservation_id);

    res.json({ ok: true, reservation_id, to_slot_time, queue_code: row.queue_code });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Seed helper for time slots (optional) ----------------------------------
// POST /api/slots/seed { site_id, date, start:"07:00", end:"17:00", interval_min:7 }
app.post('/api/slots/seed', (req, res) => {
  try {
    const { site_id, date, start, end, interval_min = 7 } = req.body || {};
    if (!site_id || !date || !start || !end) return res.status(400).json({ error: 'site_id, date, start, end required' });

    const toMin = hhmm => {
      const [h,m] = hhmm.split(':').map(n => parseInt(n,10));
      return h*60 + m;
    };
    const toHHMM = mins => {
      const h = Math.floor(mins/60).toString().padStart(2,'0');
      const m = (mins%60).toString().padStart(2,'0');
      return `${h}:${m}`;
    };

    const s = toMin(start);
    const e = toMin(end);
    const stmt = db.prepare(`
      INSERT OR IGNORE INTO time_slots (site_id, date, slot_time, is_workin)
      VALUES (?,?,?,0)
    `);
    let count = 0;
    for (let t=s; t<=e; t+=interval_min) {
      stmt.run(site_id, date, toHHMM(t));
      count++;
    }
    res.json({ ok: true, inserted: count });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('CORS origin:', CORS_ORIGIN);
});
