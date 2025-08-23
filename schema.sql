PRAGMA journal_mode=WAL;

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
  role TEXT DEFAULT 'driver',
  expires_at TEXT NOT NULL,
  attempts_left INTEGER DEFAULT 5,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes (phone);

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
  date TEXT NOT NULL,      -- YYYY-MM-DD
  slot_time TEXT NOT NULL, -- HH:MM
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
  manage_token TEXT,
  queue_code TEXT,                 -- 4-digit Probe/Confirm code
  status TEXT DEFAULT 'reserved',  -- reserved|canceled
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS facility_info (
  id INTEGER PRIMARY KEY CHECK (id=1),
  facility_phone TEXT,
  support_phone TEXT,
  updated_at TEXT
);
INSERT OR IGNORE INTO facility_info (id) VALUES (1);

CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations (site_id, date, queue_code);
