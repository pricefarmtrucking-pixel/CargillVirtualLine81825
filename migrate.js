// migrate.js — idempotent schema fixer (ESM)
import Database from 'better-sqlite3';

const DB_PATH = process.env.DB_PATH || 'data.db';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function exec(sql, label) {
  db.exec(sql);
  if (label) console.log('✓', label);
}

function tableHasColumn(table, column) {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all();
  return rows.some(r => r.name === column);
}

function ensureBaseSchema() {
  // keep your existing base schema here as you already have it
  exec(`
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
);`, 'Ensured base tables');
}

function ensureTimeSlotsNewColumns() {
  // Add columns introduced later, only if missing (idempotent)
  if (!tableHasColumn('time_slots', 'reserved_truck_id')) {
    exec(`ALTER TABLE time_slots ADD COLUMN reserved_truck_id INTEGER;`,
         'Added time_slots.reserved_truck_id');
  }
  if (!tableHasColumn('time_slots', 'reserved_at')) {
    exec(`ALTER TABLE time_slots ADD COLUMN reserved_at TEXT;`,
         'Added time_slots.reserved_at');
  }
  if (!tableHasColumn('time_slots', 'hold_token')) {
    exec(`ALTER TABLE time_slots ADD COLUMN hold_token TEXT;`,
         'Added time_slots.hold_token');
  }
  if (!tableHasColumn('time_slots', 'hold_expires_at')) {
    exec(`ALTER TABLE time_slots ADD COLUMN hold_expires_at TEXT;`,
         'Added time_slots.hold_expires_at');
  }
}

function main() {
  console.log('Running migrations against', DB_PATH);
  ensureBaseSchema();
  ensureTimeSlotsNewColumns();
  console.log('Migrations applied ✅');
}

main();
