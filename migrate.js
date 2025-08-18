// migrate.js — CommonJS
// Run with: `node migrate.js` (Render build step can call `npm run migrate`)

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_PATH || 'data.db';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function exec(sql, label) {
  if (!sql) return;
  db.exec(sql);
  if (label) console.log('✓', label);
}

function applySchema() {
  // If you maintain a schema.sql, we’ll use it; otherwise use fallback schema.
  const schemaPath = path.join(__dirname, 'schema.sql');
  if (fs.existsSync(schemaPath)) {
    const sql = fs.readFileSync(schemaPath, 'utf8');
    exec(sql, 'Applied schema.sql');
    return;
  }

  // Fallback base schema (idempotent)
  const base = `
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
  queue_code TEXT,                                -- 4‑digit probe code
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS facility_info (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  facility_phone TEXT,
  support_phone TEXT,
  updated_at TEXT
);
INSERT OR IGNORE INTO facility_info (id) VALUES (1);
`;
  exec(base, 'Applied fallback schema');
}

function ensureProbeCodeColumn() {
  // Add queue_code if missing (safe if already present), plus an index for probe lookups.
  const cols = db.prepare(`PRAGMA table_info(slot_reservations)`).all();
  const hasQueue = cols.some(c => c.name === 'queue_code');
  if (!hasQueue) {
    exec(`ALTER TABLE slot_reservations ADD COLUMN queue_code TEXT;`, 'Added queue_code column');
  }
  exec(
    `CREATE INDEX IF NOT EXISTS idx_resv_probe
       ON slot_reservations (site_id, date, queue_code);`,
    'Ensured probe index'
  );
}

function main() {
  console.log('Running migrations against', DB_PATH);
  applySchema();            // create tables if not present
  ensureProbeCodeColumn();  // upgrade path (idempotent)
  console.log('Migrations applied ✅');
}

main();
