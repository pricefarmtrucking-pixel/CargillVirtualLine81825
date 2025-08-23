// index.js — Cargill Virtual Line (ESM)
import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ---------- ENV ----------
const PORT = Number(process.env.PORT || 10000);
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const DB_PATH = process.env.DB_PATH || 'data.db';
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER= process.env.TWILIO_PHONE_NUMBER;

// ---------- DB ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Base schema (safe to re-run)
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
  queue_code TEXT,            -- 4-digit probe code
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

// ---------- Twilio (optional) ----------
let twilio = null;
const hasTwilio = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_PHONE_NUMBER;
if (hasTwilio) {
  const t = (await import('twilio')).default;
  twilio = t(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  console.log('Twilio: client initialized');
} else {
  console.log('Twilio: not configured, using SMS mock');
}
async function sendSMS(to, body) {
  if (!hasTwilio) { console.log('[SMS MOCK]', to, body); return { sent:false, mock:true }; }
  try {
    const msg = await twilio.messages.create({ from: TWILIO_PHONE_NUMBER, to, body });
    return { sent:true, sid: msg.sid };
  } catch (e) {
    console.error('Twilio error:', e?.message || e);
    return { sent:false, error:e?.message || 'twilio-failed' };
  }
}

// ---------- App ----------
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Helpers ----------
const sixDigit = () => String(Math.floor(100000 + Math.random()*900000));
const fourDigit = () => String(Math.floor(1000 + Math.random()*9000));
const normPhone = p => {
  const d = String(p||'').replace(/\D/g,'');
  if (/^\d{10}$/.test(d)) return '+1'+d;
  if (/^1\d{10}$/.test(d)) return '+'+d;
  if (/^\+1\d{10}$/.test(d)) return d;
  return null;
};
const toMin = hhmm => { const [h,m]=hhmm.split(':').map(n=>+n); return h*60+m; };
const toHHMM = mins => `${String(Math.floor(mins/60)).padStart(2,'0')}:${String(mins%60).padStart(2,'0')}`;
const todayISO = () => new Date().toISOString().slice(0,10);

// Expire holds helper
function expireHolds() {
  db.prepare(`UPDATE time_slots
              SET hold_token=NULL, hold_expires_at=NULL
              WHERE hold_expires_at IS NOT NULL
                AND hold_expires_at < CURRENT_TIMESTAMP`).run();
}

// ---------- AUTH ----------
app.post('/auth/request-code', async (req, res) => {
  try {
    const phone = normPhone(req.body?.phone);
    const role  = req.body?.role === 'admin' ? 'admin' : 'driver';
    if (!phone) return res.status(400).json({ error:'invalid phone' });

    const code = sixDigit();
    db.prepare(`INSERT INTO otp_codes (phone, code, role, expires_at)
                VALUES (?,?,?,datetime('now','+10 minutes'))`)
      .run(phone, code, role);

    const sms = await sendSMS(phone,
      role==='admin'
       ? `Cargill Admin Code: ${code}. Expires in 10 minutes.`
       : `Cargill Sign-in Code: ${code}. Expires in 10 minutes. Reply STOP to opt out.`
    );
    res.json({ ok:true, sms });
  } catch(e) {
    console.error(e); res.status(500).json({ error:'server error' });
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
      ORDER BY id DESC LIMIT 1`).get(phone, code, role);

    if (!row) return res.status(400).json({ error:'code invalid or expired' });

    db.prepare(`UPDATE otp_codes SET consumed_at=CURRENT_TIMESTAMP WHERE id=?`).run(row.id);
    res.cookie('session_phone', phone, { httpOnly:false, sameSite:'lax' });
    res.cookie('session_role' , role , { httpOnly:false, sameSite:'lax' });
    res.json({ ok:true });
  } catch(e){ console.error(e); res.status(500).json({ error:'server error' }); }
});

// ---------- SCHEDULE BUILDER (OVERWRITE OLD SLOTS) ----------
app.post('/api/sites/:id/schedule', (req,res)=>{
  try{
    const site_id = +req.params.id;
    const { date, open_time, close_time, loads_target, workins_per_hour=0 } = req.body || {};
    if(!site_id || !date || !open_time || !close_time || !loads_target)
      return res.status(400).json({ error:'missing fields' });

    // EAST(1) 5min, WEST(2) 6min minimum
    const minInt = site_id===2 ? 6 : 5;
    const start = toMin(open_time);
    const end   = toMin(close_time);
    const span  = Math.max(1, end - start);
    const interval = Math.max(minInt, Math.floor(span / Math.max(1, loads_target-1)));

    const tx = db.transaction(()=>{
      // settings
      db.prepare(`
        INSERT INTO site_settings (site_id,date,loads_target,open_time,close_time,workins_per_hour)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(site_id,date) DO UPDATE SET
          loads_target=excluded.loads_target,
          open_time=excluded.open_time,
          close_time=excluded.close_time,
          workins_per_hour=excluded.workins_per_hour,
          updated_at=CURRENT_TIMESTAMP
      `).run(site_id, date, loads_target, open_time, close_time, workins_per_hour);

      // OVERWRITE previous slots for that site/date
      db.prepare(`DELETE FROM time_slots
                  WHERE site_id=? AND date=? AND reserved_truck_id IS NULL`).run(site_id, date);
      // Keep reserved rows; clear holds
      db.prepare(`UPDATE time_slots SET hold_token=NULL, hold_expires_at=NULL
                  WHERE site_id=? AND date=?`).run(site_id, date);

      // Generate target slots
      const ins = db.prepare(`INSERT OR IGNORE INTO time_slots (site_id,date,slot_time,is_workin)
                              VALUES (?,?,?,0)`);
      for(let i=0;i<loads_target;i++){
        const t = start + i*interval;
        if (t>=start && t<=end) ins.run(site_id, date, toHHMM(t));
      }

      // Optional work-ins
      if (workins_per_hour>0){
        const step = Math.floor(60/workins_per_hour);
        for(let m=start; m<=end; m+=step){
          db.prepare(`INSERT OR IGNORE INTO time_slots (site_id,date,slot_time,is_workin)
                      VALUES (?,?,?,1)`).run(site_id, date, toHHMM(m));
        }
      }
    });
    tx();

    res.json({ ok:true, interval_min: interval });
  }catch(e){ console.error(e); res.status(500).json({ error:'server error' }); }
});

// ---------- LIST ALL SLOTS (open + reserved) ----------
app.get('/api/appointments', (req,res)=>{
  try{
    const site_id = parseInt(req.query.site_id,10);
    const date = String(req.query.date||todayISO());
    if(!site_id) return res.status(400).json({ error:'site_id required' });

    const rows = db.prepare(`
      SELECT
        s.slot_time,
        s.is_workin,
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
  }catch(e){ console.error(e); res.status(500).json({ error:'server error' }); }
});

// ---------- OPEN SLOTS FOR DRIVER ----------
app.get('/api/sites/:id/slots', (req,res)=>{
  try{
    expireHolds();
    const site_id = +req.params.id;
    const date = String(req.query.date || todayISO());
    if(!site_id) return res.status(400).json({ error:'site_id required' });

    // show open (no reservation, no hold)
    const rows = db.prepare(`
      SELECT slot_time
      FROM time_slots s
      LEFT JOIN slot_reservations r
        ON r.site_id=s.site_id AND r.date=s.date AND r.slot_time=s.slot_time
      WHERE s.site_id=? AND s.date=? AND r.id IS NULL AND s.hold_token IS NULL
      ORDER BY time(s.slot_time)
    `).all(site_id, date);

    res.json(rows.map(r=>r.slot_time));
  }catch(e){ console.error(e); res.status(500).json({ error:'server error' }); }
});

// ---------- HOLD / CONFIRM ----------
app.post('/api/slots/hold',(req,res)=>{
  expireHolds();
  const { site_id, date, slot_time } = req.body || {};
  if(!site_id || !date || !slot_time) return res.status(400).json({ error:'missing fields' });

  const row = db.prepare(`
    SELECT id, reserved_truck_id, hold_expires_at FROM time_slots
    WHERE site_id=? AND date=? AND slot_time=?`).get(site_id,date,slot_time);

  if(!row) return res.status(404).json({ error:'slot not found' });
  if(row.reserved_truck_id) return res.status(409).json({ error:'slot reserved' });
  if(row.hold_expires_at && new Date(row.hold_expires_at)>new Date())
    return res.status(409).json({ error:'slot on hold' });

  const token = crypto.randomUUID();
  db.prepare(`UPDATE time_slots
              SET hold_token=?, hold_expires_at=datetime('now','+120 seconds')
              WHERE id=?`).run(token,row.id);

  const ex = db.prepare(`SELECT hold_expires_at AS e FROM time_slots WHERE id=?`).get(row.id).e;
  res.json({ hold_token: token, expires_at: ex });
});

app.post('/api/slots/confirm', async (req,res)=>{
  expireHolds();
  const { hold_token, site_id, date, slot_time,
          driver_name, license_plate, vendor_name,
          farm_or_ticket, est_amount, est_unit, driver_phone } = req.body || {};
  if(!hold_token) return res.status(400).json({ error:'hold_token required' });

  const slot = db.prepare(`
    SELECT * FROM time_slots
    WHERE hold_token=? AND hold_expires_at > CURRENT_TIMESTAMP`).get(hold_token);
  if(!slot) return res.status(410).json({ error:'hold expired or invalid' });

  const probe = fourDigit();

  const info = db.prepare(`
    INSERT INTO slot_reservations
      (site_id,date,slot_time,driver_name,license_plate,vendor_name,
       farm_or_ticket,est_amount,est_unit,driver_phone,queue_code,status)
    VALUES (?,?,?,?,?,?,?,?,?,?,?, 'reserved')
    RETURNING id
  `).get(
    slot.site_id, slot.date, slot.slot_time,
    driver_name||null, license_plate||null, vendor_name||null,
    farm_or_ticket||null, est_amount||null, (est_unit||'BUSHELS').toUpperCase(),
    normPhone(driver_phone)||null, probe
  );

  db.prepare(`UPDATE time_slots
              SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP,
                  hold_token=NULL, hold_expires_at=NULL
              WHERE id=?`).run(info.id, slot.id);

  if (driver_phone) {
    await sendSMS(driver_phone,
      `Cargill: Confirmed ${slot.date} at ${slot.slot_time}. Probe code: ${probe}. Reply STOP to opt out.`
    );
  }
  res.status(201).json({ ok:true, reservation_id: info.id, queue_code: probe });
});

// ---------- CANCEL / REASSIGN (return probe code) ----------
app.post('/api/slots/cancel',(req,res)=>{
  const { reservation_id } = req.body || {};
  if(!reservation_id) return res.status(400).json({ error:'reservation_id required' });

  const r = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
  if(!r) return res.status(404).json({ error:'not found' });

  db.prepare(`DELETE FROM slot_reservations WHERE id=?`).run(reservation_id);
  db.prepare(`UPDATE time_slots
              SET reserved_truck_id=NULL, reserved_at=NULL
              WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?`)
    .run(r.site_id, r.date, r.slot_time, r.id);

  res.json({ ok:true, reservation_id, queue_code: r.queue_code });
});

app.post('/api/slots/reassign',(req,res)=>{
  const { reservation_id, to_slot_time } = req.body || {};
  if(!reservation_id || !to_slot_time) return res.status(400).json({ error:'missing fields' });

  const r = db.prepare(`SELECT * FROM slot_reservations WHERE id=?`).get(reservation_id);
  if(!r) return res.status(404).json({ error:'not found' });

  // ensure target slot exists
  db.prepare(`INSERT OR IGNORE INTO time_slots (site_id,date,slot_time,is_workin)
              VALUES (?,?,?,0)`).run(r.site_id, r.date, to_slot_time);

  // ensure it's free
  const tgt = db.prepare(`SELECT * FROM time_slots WHERE site_id=? AND date=? AND slot_time=?`)
                .get(r.site_id, r.date, to_slot_time);
  if(tgt.reserved_truck_id) return res.status(409).json({ error:'target slot reserved' });

  const tx = db.transaction(()=>{
    db.prepare(`UPDATE time_slots SET reserved_truck_id=NULL, reserved_at=NULL
                WHERE site_id=? AND date=? AND slot_time=? AND reserved_truck_id=?`)
      .run(r.site_id, r.date, r.slot_time, r.id);
    db.prepare(`UPDATE time_slots SET reserved_truck_id=?, reserved_at=CURRENT_TIMESTAMP
                WHERE id=?`).run(r.id, tgt.id);
    db.prepare(`UPDATE slot_reservations SET slot_time=? WHERE id=?`)
      .run(to_slot_time, reservation_id);
  });
  tx();

  res.json({ ok:true, reservation_id, to_slot_time, queue_code: r.queue_code });
});

// ---------- START ----------
app.listen(PORT, ()=> {
  console.log(`Server running on http://localhost:${PORT}`);
});
