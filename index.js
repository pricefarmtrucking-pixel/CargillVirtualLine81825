// index.js — Cargill Virtual Line (ESM, full backend, soft-disable ready)
import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

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

// ------------------------- App & Middleware ----------------------------------
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));

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
    const role  = req.body?.role === 'admin' ? 'admin' : 'driver';
    if (!phone) return res.status(400).json({ error:'invalid phone' });

    const code = sixDigit();
    db.prepare(`
      INSERT INTO otp_codes (phone, code, role, expires_at)
      VALUES (?, ?, ?, datetime('now','+10 minutes'))
    `).run(phone, code, role);

    const sms = await sendSMS(
      phone,
      role==='admin'
        ? `Cargill Admin Code: ${code}. Expires in 10 minutes.`
        : `Cargill Sign-in Code: ${code}. Expires in 10 minutes. Reply STOP to opt out.`
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
    const role  = req.body?.role === 'admin' ? 'admin' : 'driver';
    if (!phone || !/^\d{6}$/.test(code)) return res.status(400).json({ error:'invalid' });

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
app.post('/api/sites/:id/slots/preview', (req, res) => {
  try {
    const site_id = +req.params.id;
    const { date, open_time, close_time, loads_target, workins_per_hour = 0 } = req.body || {};
    if (!site_id || !date || !open_time || !close_time || !loads_target)
      return res.status(400).json({ error:'missing fields' });

    const minInt = site_id === 2 ? 6 : 5;
    const start  = toMin(open_time);
    const end    = toMin(close_time);
    const span   = Math.max(1, end - start);
    const interval = Math.max(minInt, Math.floor(span / Math.max(1, loads_target-1)));

    const times = [];
    for (let i=0; i<loads_target; i++) {
      const t = start + i*interval;
      if (t>=start && t<=end) times.push({ slot_time: toHHMM(t), is_workin: 0 });
    }
    if (workins_per_hour > 0) {
      const step = Math.max(1, Math.floor(60/workins_per_hour));
      for (let m=start; m<=end; m+=step) {
        times.push({ slot_time: toHHMM(m), is_workin: 1 });
      }
      times.sort((a,b)=> toMin(a.slot_time)-toMin(b.slot_time));
    }

    res.json({ ok:true, interval_min: interval, items: times });
  } catch (e) {
    console.error('/api/sites/:id/slots/preview', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Schedule PUBLISH (overwrite) ----------------------
// POST /api/sites/:id/schedule
// Body: { date, open_time, close_time, loads_target, disabled_slots }
app.post('/api/sites/:id/schedule', (req, res) => {
  const DEBUG = process.env.NODE_ENV !== 'production';

  try {
    const site_id = Number(req.params.id);
    let {
      date,
      open_time = '',
      close_time = '',
      loads_target,
      disabled_slots = 0
    } = req.body || {};

    // normalize & validate
    date = String(date || '').trim();
    open_time = String(open_time || '').trim();
    close_time = String(close_time || '').trim();
    loads_target = Number(loads_target);
    disabled_slots = Number(disabled_slots) || 0;

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
    if (disabled_slots < 0) disabled_slots = 0;

    const toMin  = t => { const [h,m] = t.split(':').map(Number); return h*60+m; };
    const toHHMM = mins => `${String(Math.floor(mins/60)).padStart(2,'0')}:${String(mins%60).padStart(2,'0')}`;

    // EAST(1)=5m min; WEST(2)=6m min
    const minInt = site_id === 2 ? 6 : 5;
    const start  = toMin(open_time);
    const end    = toMin(close_time);
    if (!(end > start)) return res.status(400).json({ error: 'close must be after open' });

    const span     = end - start;
    const interval = Math.max(minInt, Math.floor(span / Math.max(1, loads_target - 1)));

    // Evenly spaced target times
    const targetTimes = [];
    for (let i = 0; i < loads_target; i++) {
      const t = start + i * interval;
      if (t >= start && t <= end) targetTimes.push(toHHMM(t));
    }

    // Decide which to disable: e.g. 80 total, 10 disabled -> every 8th
    const disableEvery = disabled_slots > 0 ? Math.round(loads_target / disabled_slots) : 0;
    const disableSet = new Set();
    if (disableEvery >= 2) {
      for (let i = disableEvery - 1; i < targetTimes.length; i += disableEvery) {
        disableSet.add(targetTimes[i]);
      }
    }

    // Transaction
    const tx = db.transaction(() => {
      // Settings
      db.prepare(`
        INSERT INTO site_settings (site_id, date, loads_target, open_time, close_time, workins_per_hour)
        VALUES (?, ?, ?, ?, ?, 0)
        ON CONFLICT(site_id, date) DO UPDATE SET
          loads_target     = excluded.loads_target,
          open_time        = excluded.open_time,
          close_time       = excluded.close_time,
          workins_per_hour = excluded.workins_per_hour,
          updated_at       = CURRENT_TIMESTAMP
      `).run(site_id, date, loads_target, open_time, close_time);

      // Clear holds (keep reservations)
      db.prepare(`
        UPDATE time_slots
           SET hold_token=NULL, hold_expires_at=NULL
         WHERE site_id=? AND date=?
      `).run(site_id, date);

      // Upsert each target time (respect disabled flag)
      const upsert = db.prepare(`
        INSERT INTO time_slots (site_id, date, slot_time, is_workin, reserved_truck_id, reserved_at, hold_token, hold_expires_at, disabled)
        VALUES (?, ?, ?, 0, NULL, NULL, NULL, NULL, ?)
        ON CONFLICT(site_id, date, slot_time, is_workin) DO UPDATE SET
          disabled = excluded.disabled
      `);
      for (const t of targetTimes) {
        upsert.run(site_id, date, t, disableSet.has(t) ? 1 : 0);
      }

      // Soft‑disable *open* regular slots not in the new target list
      if (targetTimes.length) {
        const ph = targetTimes.map(() => '?').join(',');
        db.prepare(`
          UPDATE time_slots
             SET disabled = 1
           WHERE site_id = ?
             AND date    = ?
             AND is_workin = 0
             AND (reserved_truck_id IS NULL OR reserved_truck_id = 0)
             AND slot_time NOT IN (${ph})
        `).run(site_id, date, ...targetTimes);
      } else {
        db.prepare(`
          UPDATE time_slots
             SET disabled = 1
           WHERE site_id = ?
             AND date    = ?
             AND is_workin = 0
             AND (reserved_truck_id IS NULL OR reserved_truck_id = 0)
        `).run(site_id, date);
      }
    });

    // Run tx and respond
    tx();
    return res.json({ ok: true, interval_min: interval });
  } catch (e) {
    console.error('/api/sites/:id/schedule', e);
    return res.status(500).json({ error: 'server error' });
  }
});

    // run the tx and respond (keep returns INSIDE the route)
    try {
      tx();
    } catch (sqlErr) {
      console.error('SQL error in /api/sites/:id/schedule:', sqlErr);
      return res.status(500).json({ error: DEBUG ? String(sqlErr) : 'server error' });
    }

    return res.json({ ok: true, interval_min: interval });
  } catch (e) {
    console.error('/api/sites/:id/schedule', e);
    return res.status(500).json({ error: 'server error' });
  }
});

    try {
      tx();
    } catch (sqlErr) {
      console.error('SQL error in /api/sites/:id/schedule:', sqlErr);
      return res.status(500).json({ error: DEBUG ? String(sqlErr) : 'server error' });
    }

    return res.json({ ok: true, interval_min: interval });
  } catch (e) {
    console.error('/api/sites/:id/schedule', e);
    return res.status(500).json({ error: 'server error' });
  }
});

    try { tx(); }
    catch (sqlErr) {
      console.error('SQL error in /api/sites/:id/schedule:', sqlErr);
      return res.status(500).json({ error: DEBUG ? String(sqlErr) : 'server error' });
    }

    return res.json({ ok: true, interval_min: interval });
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

  if (driver_phone) {
    await sendSMS(
      driver_phone,
      `Cargill: Confirmed ${slot.date} at ${slot.slot_time}. Probe code: ${probe}. Reply STOP to opt out.`
    );
  }

  res.status(201).json({ ok:true, reservation_id: info.id, queue_code: probe });
});
// ------------------- Probe Upsert (create or edit reservation) -------------------
// POST /api/slots/probe-upsert
// Body:
// {
//   site_id: 1,
//   date: "2025-08-23",
//   slot_time: "07:14",
//   reservation_id: 123,                // OPTIONAL: if provided, we edit; otherwise create
//   driver_name: "...", license_plate:"...", vendor_name:"...",
//   farm_or_ticket:"...", est_amount:1000, est_unit:"BUSHELS",
//   driver_phone:"+15635551234",        // optional
//   notify: true,                        // optional: send SMS
//   reason: "Updated by probe"           // optional: added to SMS for updates
// }
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

    const normPhone = p => {
      const d = String(p||'').replace(/\D/g,'');
      if (/^\d{10}$/.test(d)) return '+1'+d;
      if (/^1\d{10}$/.test(d)) return '+'+d;
      if (/^\+1\d{10}$/.test(d)) return d;
      return null;
    };
    const phoneNorm = normPhone(driver_phone);

    // Helper: fetch time slot row
    const slot = db.prepare(`
      SELECT * FROM time_slots
      WHERE site_id=? AND date=? AND slot_time=?
    `).get(site_id, date, slot_time);

    if (!slot) {
      return res.status(404).json({ error: 'slot not found' });
    }

    // If creating a new reservation into an open slot, we need a probe code.
    const newProbeCode = () => String(Math.floor(1000 + Math.random()*9000));

    let created = false;
    let updated = false;
    let queue_code = null;
    let resvId = reservation_id || null;

    const tx = db.transaction(() => {
      if (reservation_id) {
        // UPDATE existing reservation (fields only)
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

        // keep queue_code
        queue_code = prev.queue_code || null;
        updated = true;

        // ensure the time_slots row points to this reservation (in case it was open)
        db.prepare(`
          UPDATE time_slots
             SET reserved_truck_id = ?
           WHERE site_id=? AND date=? AND slot_time=? 
        `).run(reservation_id, site_id, date, slot_time);
      } else {
        // CREATE new reservation if slot is open (not reserved)
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

        // mark slot reserved
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

    // SMS (best‑effort)
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
      } catch { /* ignore sms errors */ }
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

  res.json({ ok:true, reservation_id, to_slot_time, queue_code: r.queue_code });
});
// --- ADMIN: update reservation (edit existing) ---
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
    `).run(driver_name, driver_phone, license_plate,
           vendor_name, farm_or_ticket, est_amount, est_unit, reservation_id);

    // optional notify
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

// --- ADMIN: reserve an open slot (create new reservation manually) ---
app.post('/api/admin/reserve', async (req, res) => {
  try {
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

    if (driver_phone) {
      const msg = `Cargill: Reserved ${date} at ${slot_time}. Probe code: ${probe}. Reply STOP to opt out.`;
      await sendSMS(driver_phone, msg);
    }

    res.json({ ok:true, reservation_id: info.id, queue_code: probe });
  } catch (e) {
    console.error('admin-reserve', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Enable / Disable Open Slots -----------------------
// Body: { site_id, date, slot_times: ["HH:MM", ...] }
// NOTE: These act only on the time_slots rows for the given site/date/times.
//       They don't touch reservations; UI already filters to open rows.

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

// Enable/Disable selected times (soft hide from drivers)
app.post('/api/slots/disable', (req, res) => {
  try {
    const { site_id, date, slot_times = [], disable = true } = req.body || {};
    if (!site_id || !date || !Array.isArray(slot_times) || !slot_times.length) {
      return res.status(400).json({ error:'site_id, date, slot_times required' });
    }
    const marks = slot_times.map(()=>'?').join(',');
    const result = db.prepare(`
      UPDATE time_slots
         SET disabled = ?
       WHERE site_id = ? AND date = ? AND slot_time IN (${marks})
    `).run(disable ? 1 : 0, site_id, date, ...slot_times);
    res.json({ ok:true, updated: result.changes });
  } catch (e) {
    console.error('/api/slots/disable', e);
    res.status(500).json({ error:'server error' });
  }
});

// ------------------------- Admin: create (reserve) a slot --------------------
// POST /api/admin/reserve
// Body: { site_id, date, slot_time, driver_name?, license_plate?, vendor_name?,
//         farm_or_ticket?, est_amount?, est_unit?, driver_phone?, queue_code? }
app.post('/api/admin/reserve', (req, res) => {
  try {
    const {
      site_id, date, slot_time,
      driver_name, license_plate, vendor_name,
      farm_or_ticket, est_amount, est_unit, driver_phone, queue_code
    } = req.body || {};

    if (!site_id || !date || !slot_time) {
      return res.status(400).json({ error: 'site_id, date, slot_time required' });
    }

    // Ensure slot exists and is not disabled/reserved
    const slot = db.prepare(`
      SELECT * FROM time_slots
      WHERE site_id=? AND date=? AND slot_time=? AND (disabled IS NULL OR disabled=0)
    `).get(site_id, date, slot_time);

    if (!slot) return res.status(404).json({ error: 'slot not found or disabled' });
    if (slot.reserved_truck_id) return res.status(409).json({ error: 'slot already reserved' });

    const probe = queue_code || String(Math.floor(1000 + Math.random()*9000));

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

    return res.status(201).json({ ok: true, reservation_id: info.id, queue_code: probe });
  } catch (e) {
    console.error('/api/admin/reserve', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ------------------------- Admin: update reservation fields ------------------
// POST /api/admin/update-reservation
// Body: { reservation_id, driver_name?, license_plate?, vendor_name?, farm_or_ticket?,
//         est_amount?, est_unit?, driver_phone? }
app.post('/api/admin/update-reservation', (req, res) => {
  try {
    const {
      reservation_id, driver_name, license_plate, vendor_name,
      farm_or_ticket, est_amount, est_unit, driver_phone
    } = req.body || {};
    if (!reservation_id) return res.status(400).json({ error: 'reservation_id required' });

    const setParts = [];
    const vals = [];
    const push = (col, val) => { setParts.push(`${col}=?`); vals.push(val); };

    if (driver_name !== undefined)   push('driver_name', driver_name || null);
    if (license_plate !== undefined) push('license_plate', license_plate || null);
    if (vendor_name !== undefined)   push('vendor_name', vendor_name || null);
    if (farm_or_ticket !== undefined)push('farm_or_ticket', farm_or_ticket || null);
    if (est_amount !== undefined)    push('est_amount', est_amount ?? null);
    if (est_unit !== undefined)      push('est_unit', (est_unit || 'BUSHELS').toUpperCase());
    if (driver_phone !== undefined)  push('driver_phone', driver_phone ? normPhone(driver_phone) : null);

    if (!setParts.length) return res.json({ ok: true, updated: 0 });

    const sql = `UPDATE slot_reservations SET ${setParts.join(', ')} WHERE id=?`;
    vals.push(reservation_id);
    const info = db.prepare(sql).run(...vals);
    return res.json({ ok: true, updated: info.changes });
  } catch (e) {
    console.error('/api/admin/update-reservation', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ------------------------- Health / Debug ------------------------------------
app.get('/healthz', (_req, res) => res.json({ ok:true }));
app.get('/debug/env', (_req, res) => {
  res.json({
    PORT, CORS_ORIGIN, DB_PATH,
    hasTwilio: !!(TWILIO_SID && TWILIO_AUTH && TWILIO_FROM)
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
// POST /api/slots/add-times
// Body:
// {
//   site_id: 1,
//   date: "2025-08-23",
//   start: "15:00",               // inclusive
//   end:   "17:00",               // inclusive
//   loads_target: 20,             // either this...
//   // OR interval_min: 5,        // ...or this (if provided, overrides computed interval)
//   is_workin: 0                  // optional (default 0)
// }
// Behavior:
// - Inserts *new* rows into time_slots for the given range; never deletes anything.
// - Existing rows are left untouched; reservations untouched.
// - Newly created rows are enabled (disabled=0).
app.post('/api/slots/add-times', (req, res) => {
  try {
    const {
      site_id,
      date,
      start,
      end,
      loads_target,
      interval_min,
      is_workin = 0
    } = req.body || {};

    // --- validation
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

    const toMin = (t) => { const [h,m] = String(t).split(':').map(Number); return h*60+m; };
    const toHHMM = (mins) => `${String(Math.floor(mins/60)).padStart(2,'0')}:${String(mins%60).padStart(2,'0')}`;

    const s = toMin(start);
    const e = toMin(end);
    if (!(e >= s)) return res.status(400).json({ ok:false, error: 'end must be >= start' });

    // Compute interval:
    // If interval_min provided, use it; else compute from loads_target + site min.
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

    // Build times list (inclusive range)
    const newTimes = [];
    for (let t = s; t <= e; t += step) {
      newTimes.push(toHHMM(t));
    }

    // Insert-or-ignore; ensure enabled (disabled=0) for these rows
    const ins = db.prepare(`
      INSERT INTO time_slots
        (site_id, date, slot_time, is_workin, reserved_truck_id, reserved_at, hold_token, hold_expires_at, disabled)
      VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, 0)
      ON CONFLICT(site_id, date, slot_time, is_workin) DO UPDATE SET
        disabled = 0
    `);

    let inserted = 0;
    const tx = db.transaction(() => {
      for (const t of newTimes) {
        const info = ins.run(site_id, date, t, is_workin ? 1 : 0);
        // When it hits ON CONFLICT UPDATE, changes may be 0 or 1 depending on SQLite version;
        // we’ll just report how many *attempts* were made and return the list.
        inserted += 1;
      }
    });
    tx();

    return res.json({ ok:true, inserted, slot_times: newTimes });
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
