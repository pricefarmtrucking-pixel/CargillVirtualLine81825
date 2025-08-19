/**
 * Cargill Virtual Line — Backend (CommonJS)
 * -----------------------------------------
 * - Express + better-sqlite3
 * - Cookie session via signed token (very light)
 * - OTP code login for driver / probe / admin (role-aware)
 * - Twilio SMS (optional; auto-disables if creds not present)
 * - Appointments API returns joined slots+reservations and includes probe_code
 * - Reserve / reassign / cancel respond with probe_code to help Probe desk
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();

// ---- Config ---------------------------------------------------------------
const PORT = process.env.PORT || 10000;
const ORIGIN = (process.env.CORS_ORIGIN || '').trim(); // e.g. https://cargill-line-1.onrender.com
const DB_PATH = process.env.DB_PATH || 'data.db';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret';
const PROD = (process.env.NODE_ENV || '').toLowerCase() === 'production';

// Twilio (optional)
let twilioClient = null;
const TWILIO_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_FROM = process.env.TWILIO_PHONE_NUMBER;
if (TWILIO_SID && TWILIO_TOKEN && TWILIO_FROM) {
  try {
    twilioClient = require('twilio')(TWILIO_SID, TWILIO_TOKEN);
    console.log('Twilio: client initialized');
  } catch (e) {
    console.warn('Twilio init failed, SMS disabled:', e.message);
    twilioClient = null;
  }
} else {
  console.log('Twilio not configured — SMS will be logged only.');
}

// ---- Middleware -----------------------------------------------------------
app.use(express.json());
app.use(cookieParser(SESSION_SECRET));
if (ORIGIN) {
  app.use(cors({
    origin: ORIGIN,
    credentials: true,
  }));
}
app.set('trust proxy', 1);

// ---- DB ------------------------------------------------------------------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Helpers to run queries
function all(sql, params = []) {
  return db.prepare(sql).all(params);
}
function get(sql, params = []) {
  return db.prepare(sql).get(params);
}
function run(sql, params = []) {
  return db.prepare(sql).run(params);
}

// ---- Session helpers ------------------------------------------------------
function signToken(payload) {
  const raw = JSON.stringify(payload);
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(raw)
    .digest('hex');
  return Buffer.from(`${raw}|${sig}`, 'utf8').toString('base64url');
}
function verifyToken(token) {
  try {
    const buf = Buffer.from(token, 'base64url').toString('utf8');
    const [raw, sig] = buf.split('|');
    const expSig = crypto.createHmac('sha256', SESSION_SECRET).update(raw).digest('hex');
    if (sig !== expSig) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
function setSessionCookie(res, data) {
  const token = signToken(data);
  res.cookie('session', token, {
    httpOnly: true,
    secure: PROD,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    signed: false,
  });
}
function readSession(req) {
  const token = req.cookies && req.cookies.session;
  if (!token) return null;
  return verifyToken(token);
}

// ---- OTP helpers ----------------------------------------------------------
function gen6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function genProbeCode() {
  // 4-digit, avoid leading zero
  return String(Math.floor(1000 + Math.random() * 9000));
}
function normalizeUS(phone) {
  if (!phone) return null;
  const d = String(phone).replace(/\D/g, '');
  if (/^\d{10}$/.test(d)) return '+1' + d;
  const m = d.match(/^1?(\d{10})$/);
  return m ? '+1' + m[1] : null;
}

// ---- Public: OTP request --------------------------------------------------
app.post('/auth/request-code', (req, res) => {
  try {
    const role = (req.body.role || 'driver').toLowerCase(); // 'driver' | 'probe' | 'admin'
    const phone = normalizeUS(req.body.phone);
    if (!phone) return res.status(400).json({ error: 'valid phone required' });

    // Create OTP
    const code = gen6();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    run(
      `INSERT INTO otp_codes (phone, code, expires_at, attempts_left)
       VALUES (?, ?, ?, 5)`,
      [phone, code, expiresAt]
    );

    // Send SMS if Twilio available
    const smsText = `Cargill: Your ${role} code is ${code}. Reply STOP to opt out.`;
    if (twilioClient) {
      twilioClient.messages
        .create({ to: phone, from: TWILIO_FROM, body: smsText })
        .then(() => console.log('SMS sent to', phone))
        .catch((e) => console.warn('SMS error:', e.message));
    } else {
      console.log('[SMS MOCK]', phone, smsText);
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('/auth/request-code error', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Public: OTP verify ---------------------------------------------------
app.post('/auth/verify', (req, res) => {
  try {
    const role = (req.body.role || 'driver').toLowerCase();
    const phone = normalizeUS(req.body.phone);
    const code = String(req.body.code || '').trim();
    if (!phone || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'phone and 6-digit code required' });
    }

    const row = get(
      `SELECT * FROM otp_codes
       WHERE phone = ? AND code = ?
       ORDER BY id DESC LIMIT 1`,
      [phone, code]
    );
    if (!row) return res.status(400).json({ error: 'invalid code' });

    const now = Date.now();
    const expMs = Date.parse(row.expires_at || 0);
    if (!expMs || expMs < now) return res.status(400).json({ error: 'code expired' });

    if (row.attempts_left <= 0 || row.consumed_at) {
      return res.status(400).json({ error: 'code already used' });
    }

    run(`UPDATE otp_codes SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?`, [row.id]);

    // Create a cookie session
    setSessionCookie(res, { phone, role, ts: Date.now() });

    res.json({ ok: true, role });
  } catch (e) {
    console.error('/auth/verify error', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Guard (optional for write endpoints) --------------------------------
function requireAdmin(req, res, next) {
  const s = readSession(req);
  if (!s || s.role !== 'admin') {
    return res.status(401).json({ error: 'admin session required' });
  }
  next();
}

// ---- Appointments: fetch for facility page --------------------------------
/**
 * Request: { site_id: number, date: 'YYYY-MM-DD' }
 * Response: { appointments: Array<...> }
 * Always returns JSON; includes probe_code for reservations.
 */
app.post('/api/appointments', (req, res) => {
  try {
    const { site_id, date } = req.body || {};
    if (!site_id || !date) {
      return res.status(400).json({ error: 'site_id and date required' });
    }

    // Try to build from time_slots, left-joining current day reservations.
    // If time_slots missing/empty, fall back to just reservations.
    const slots = all(
      `SELECT id, slot_time, is_workin
         FROM time_slots
        WHERE site_id = ? AND date = ?
        ORDER BY time(slot_time) ASC`,
      [site_id, date]
    );

    const reservations = all(
      `SELECT id, site_id, date, slot_time, driver_name AS driver, license_plate AS plate,
              vendor_name AS vendor, farm_or_ticket AS farm_ticket,
              est_amount, est_unit AS unit, driver_phone AS phone,
              queue_code, 'Reserved' AS status
         FROM slot_reservations
        WHERE site_id = ? AND date = ?
        ORDER BY time(slot_time) ASC`,
      [site_id, date]
    );

    let rows = [];

    if (slots.length) {
      // Map reservations by time for quick match
      const byKey = new Map();
      for (const r of reservations) {
        byKey.set(`${r.slot_time}|${r.site_id}`, r);
      }
      for (const sRow of slots) {
        const key = `${sRow.slot_time}|${site_id}`;
        const r = byKey.get(key) || null;
        rows.push({
          time: sRow.slot_time,
          driver: r?.driver || null,
          plate: r?.plate || null,
          vendor: r?.vendor || null,
          farm_ticket: r?.farm_ticket || null,
          est_amount: r?.est_amount || null,
          unit: r?.unit || null,
          phone: r?.phone || null,
          probe_code: r?.queue_code || null,
          status: r ? 'Reserved' : 'Open',
          reservation_id: r?.id || null,
          is_workin: !!sRow.is_workin,
        });
      }
    } else {
      // Fallback: just show reservations we have
      rows = reservations.map((r) => ({
        time: r.slot_time,
        driver: r.driver || null,
        plate: r.plate || null,
        vendor: r.vendor || null,
        farm_ticket: r.farm_ticket || null,
        est_amount: r.est_amount || null,
        unit: r.unit || null,
        phone: r.phone || null,
        probe_code: r.queue_code || null,
        status: 'Reserved',
        reservation_id: r.id,
        is_workin: 0,
      }));
    }

    return res.json({ appointments: rows });
  } catch (e) {
    console.error('/api/appointments error', e);
    res.status(500).json({ error: 'server error', detail: e.message });
  }
});

// ---- Reserve / Reassign / Cancel -----------------------------------------
/**
 * Reserve a slot for a driver (admin/probe use or driver confirm).
 * Body:
 * {
 *   site_id, date, slot_time,
 *   driver_name, license_plate, vendor_name, farm_or_ticket,
 *   est_amount, est_unit, driver_phone
 * }
 */
app.post('/api/slots/reserve', (req, res) => {
  try {
    const b = req.body || {};
    const required = ['site_id', 'date', 'slot_time'];
    for (const k of required) {
      if (!b[k]) return res.status(400).json({ error: `${k} required` });
    }

    const phone = normalizeUS(b.driver_phone);
    const probe = genProbeCode();

    const result = run(
      `INSERT INTO slot_reservations
         (site_id, date, slot_time, truck_id, license_plate, driver_name,
          driver_phone, vendor_name, farm_or_ticket, est_amount, est_unit,
          manage_token, queue_code)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        b.site_id, b.date, b.slot_time, null,
        b.license_plate || null, b.driver_name || null, phone || null,
        b.vendor_name || null, b.farm_or_ticket || null,
        b.est_amount || null, b.est_unit || null,
        crypto.randomUUID(), probe
      ]
    );

    // SMS confirmation (optional)
    if (phone) {
      const txt = `Cargill: Confirmed ${b.date} at ${b.slot_time} (${Number(b.site_id) === 1 ? 'EAST' : 'WEST'}). Code ${probe}. Reply STOP to opt out.`;
      if (twilioClient) {
        twilioClient.messages.create({ to: phone, from: TWILIO_FROM, body: txt })
          .catch(e => console.warn('SMS error:', e.message));
      } else {
        console.log('[SMS MOCK]', phone, txt);
      }
    }

    return res.json({
      ok: true,
      reservation_id: result.lastInsertRowid,
      probe_code: probe,
    });
  } catch (e) {
    console.error('/api/slots/reserve error', e);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * Reassign an existing reservation to a new time.
 * Body: { reservation_id, to_slot_time }
 */
app.post('/api/slots/reassign', (req, res) => {
  try {
    const { reservation_id, to_slot_time } = req.body || {};
    if (!reservation_id || !to_slot_time) {
      return res.status(400).json({ error: 'reservation_id and to_slot_time required' });
    }
    const row = get(`SELECT * FROM slot_reservations WHERE id = ?`, [reservation_id]);
    if (!row) return res.status(404).json({ error: 'reservation not found' });

    run(`UPDATE slot_reservations SET slot_time = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
        [to_slot_time, reservation_id]);

    // Echo probe_code so the Probe desk can still match
    return res.json({ ok: true, reservation_id, slot_time: to_slot_time, probe_code: row.queue_code || null });
  } catch (e) {
    console.error('/api/slots/reassign error', e);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * Cancel a reservation.
 * Body: { reservation_id }
 */
app.post('/api/slots/cancel', (req, res) => {
  try {
    const { reservation_id } = req.body || {};
    if (!reservation_id) return res.status(400).json({ error: 'reservation_id required' });

    const row = get(`SELECT * FROM slot_reservations WHERE id = ?`, [reservation_id]);
    if (!row) return res.status(404).json({ error: 'reservation not found' });

    run(`DELETE FROM slot_reservations WHERE id = ?`, [reservation_id]);

    // Echo probe_code for record
    return res.json({ ok: true, reservation_id, probe_code: row.queue_code || null });
  } catch (e) {
    console.error('/api/slots/cancel error', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Health / root --------------------------------------------------------
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => {
  res.type('text/plain').send('Cargill Virtual Line — API OK');
});

// ---- Start ---------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  if (ORIGIN) console.log('CORS origin:', ORIGIN);
});
