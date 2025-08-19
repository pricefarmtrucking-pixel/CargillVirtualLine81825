// index.js — CommonJS version
// Main Express server for Cargill Virtual Line

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const Database = require('better-sqlite3');
const { customAlphabet } = require('nanoid');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 10000;
const DB_PATH = process.env.DB_PATH || 'data.db';

// Database setup
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Twilio setup
const twilio = require('twilio');
const twilioClient = process.env.TWILIO_SID && process.env.TWILIO_AUTH
  ? twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH)
  : null;

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));
app.use(bodyParser.json());
app.use(express.static('public'));

// Utility: random 6-digit code
function randomCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Utility: random 4-digit probe code
const probeCode = customAlphabet('0123456789', 4);

// --- Auth APIs ---
// Request OTP
app.post('/auth/request-code', (req, res) => {
  const { phone, role } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });

  const code = randomCode();
  const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.prepare(`INSERT INTO otp_codes (phone, code, expires_at)
              VALUES (?, ?, ?)
  `).run(phone, code, expires);

  console.log(`Generated OTP for ${phone} role=${role}: ${code}`);

  if (twilioClient) {
    twilioClient.messages.create({
      from: process.env.TWILIO_FROM,
      to: phone,
      body: `[Cargill Virtual Line] Your ${role || 'user'} code is: ${code}`
    }).then(m => console.log('Twilio SMS sent', m.sid))
      .catch(err => console.error('Twilio error', err));
  }

  res.json({ ok: true });
});

// Verify OTP
app.post('/auth/verify', (req, res) => {
  const { phone, code, role } = req.body;
  if (!phone || !code) return res.status(400).json({ error: 'Missing phone/code' });

  const row = db.prepare(`
    SELECT * FROM otp_codes
    WHERE phone=? AND code=? AND consumed_at IS NULL
    ORDER BY id DESC LIMIT 1
  `).get(phone, code);

  if (!row) return res.status(400).json({ error: 'Invalid code' });
  if (new Date(row.expires_at) < new Date()) {
    return res.status(400).json({ error: 'Code expired' });
  }

  db.prepare(`UPDATE otp_codes SET consumed_at=CURRENT_TIMESTAMP WHERE id=?`).run(row.id);

  // Role-specific handling
  if (role === 'admin') {
    return res.json({ ok: true, redirect: 'facility-schedule.html' });
  }
  if (role === 'probe') {
    return res.json({ ok: true, redirect: 'appointments.html' });
  }

  // Default: driver flow
  res.json({ ok: true, redirect: 'timeslots-select.html' });
});

// --- Time Slot APIs ---
// Example: Get slots
app.get('/api/slots', (req, res) => {
  const { site = 1, date } = req.query;
  if (!date) return res.status(400).json({ error: 'Missing date' });

  const slots = db.prepare(`
    SELECT * FROM time_slots
    WHERE site_id=? AND date=?
    ORDER BY slot_time
  `).all(site, date);

  res.json({ slots });
});

// Example: Reserve a slot
app.post('/api/reserve', (req, res) => {
  const { site_id, date, slot_time, driver_phone, driver_name } = req.body;
  if (!site_id || !date || !slot_time) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    const queueCode = probeCode();
    db.prepare(`
      INSERT INTO slot_reservations 
        (site_id, date, slot_time, driver_phone, driver_name, queue_code)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(site_id, date, slot_time, driver_phone, driver_name, queueCode);

    res.json({ ok: true, queueCode });
  } catch (err) {
    console.error('Reserve error', err);
    res.status(500).json({ error: 'Reservation failed' });
  }
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`CORS origin: ${process.env.CORS_ORIGIN || '*'}`);
});
