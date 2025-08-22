// migrate.js  (ESM)
// Run during build: `node migrate.js`

import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const DB_PATH = process.env.DB_PATH || 'data.db';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function exec(sql, label) {
  if (!sql) return;
  db.exec(sql);
  if (label) console.log('✓', label);
}

function tableHasColumn(table, col) {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all();
  return rows.some(r => r.name === col);
}

function indexExists(table, indexName) {
  const rows = db.prepare(`PRAGMA index_list(${table})`).all();
  return rows.some(r => r.name === indexName);
}

function ensureSchema() {
  // 1) If you keep schema.sql in the repo, use it
  const schemaPath = path.join(__dirname, 'schema.sql');
  if (fs.existsSync(schemaPath)) {
    const sql = fs.readFileSync(schemaPath, 'utf8');
    exec(sql, 'Applied schema.sql');
    return;
  }

  // 2) Fallback (idempotent) schema if schema.sql is absent
  const fallback = `
CREATE TABLE IF NOT EXISTS users (
  phone TEXT PRIMARY KEY,
  last_login_at TEXT,
  is_banned INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  role  TEXT DEFAULT 'driver',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
  date TEXT NOT NULL,     -- YYYY-MM-DD
  slot_time TEXT NOT NULL, -- HH:MM
  is_workin INTEGER DEFAULT 0,
  UNIQUE(site_id, date, slot_time, is_workin)
);
CREATE TABLE IF NOT EXISTS slot_reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  date TEXT NOT NULL,       -- YYYY-MM-DD
  slot_time TEXT NOT NULL,  -- HH:MM
  driver_name TEXT,
  license_plate TEXT,
  vendor_name TEXT,
  farm_or_ticket TEXT,
  est_amount REAL,
  est_unit TEXT,
  driver_phone TEXT,
  manage_token TEXT,        -- for change/cancel link
  queue_code TEXT,          -- 4-digit probe/confirm code
  status TEXT DEFAULT 'reserved', -- 'reserved'|'cancelled' etc.
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS facility_info (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  facility_phone TEXT,
  support_phone  TEXT,
  updated_at TEXT
);
INSERT OR IGNORE INTO facility_info (id) VALUES (1);
`;
  exec(fallback, 'Applied fallback schema');
}

function ensureQueueCodeColumn() {
  // Add queue_code if it doesn’t exist yet
  if (!tableHasColumn('slot_reservations', 'queue_code')) {
    exec(`ALTER TABLE slot_reservations ADD COLUMN queue_code TEXT;`, 'Added slot_reservations.queue_code');
  }
  // Add status if you didn’t have it yet (handy for admin)
  if (!tableHasColumn('slot_reservations', 'status')) {
    exec(`ALTER TABLE slot_reservations ADD COLUMN status TEXT DEFAULT 'reserved';`, 'Added slot_reservations.status');
  }
  // Create probe lookup index (safe if already exists)
  if (!indexExists('slot_reservations', 'idx_resv_probe')) {
    exec(`CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations (site_id, date, queue_code);`, 'Ensured idx_resv_probe');
  }
}

function backfillMissingProbeCodes() {
  // Find reservations without a queue_code and give them a random 4‑digit (0000–9999)
  const missing = db.prepare(`SELECT id FROM slot_reservations WHERE queue_code IS NULL OR queue_code=''`).all();
  if (missing.length === 0) return;

  const upd = db.prepare(`UPDATE slot_reservations SET queue_code = ? WHERE id = ?`);
  const tx = db.transaction((rows) => {
    for (const row of rows) {
      const code = String(Math.floor(Math.random()*10000)).padStart(4,'0');
      upd.run(code, row.id);
    }
  });
  tx(missing);
  console.log(`✓ Back‑filled ${missing.length} reservation(s) with queue_code`);
}

/** OPTIONAL: make sure time_slots exists for displaying open times
 *  If you already keep time_slots in schema.sql you can keep this anyway—it’s idempotent.
 */
function ensureTimeSlotsTable() {
  exec(`
CREATE TABLE IF NOT EXISTS time_slots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  slot_time TEXT NOT NULL,
  is_workin INTEGER DEFAULT 0,
  UNIQUE(site_id, date, slot_time, is_workin)
);`, 'Ensured time_slots table');
}

/** OPTIONAL: seed helper if you want to generate empty slots in a migration.
 *  Call seedDay(...) only when you explicitly want to create a day (commented by default).
 */
function seedDay({ siteId=1, date, loadsTarget=80, open='07:00', close='17:00' }) {
  // Compute interval (rounded down) from open..close that fits loadsTarget
  const [oh, om] = open.split(':').map(Number);
  const [ch, cm] = close.split(':').map(Number);
  const startMin = oh*60 + om;
  const endMin   = ch*60 + cm;
  const span     = Math.max(1, endMin - startMin);
  const interval = Math.max(1, Math.floor(span / Math.max(1, loadsTarget)));

  const insert = db.prepare(`
    INSERT OR IGNORE INTO time_slots (site_id, date, slot_time, is_workin)
    VALUES (?, ?, ?, 0)
  `);

  const tx = db.transaction(() => {
    for (let m = startMin; m < endMin; m += interval) {
      const hh = String(Math.floor(m/60)).padStart(2,'0');
      const mm = String(m%60).padStart(2,'0');
      insert.run(siteId, date, `${hh}:${mm}`);
    }
  });
  tx();
  console.log(`✓ Seeded ${date} site ${siteId} with ~${Math.ceil(span/interval)} slots`);
}

function main() {
  console.log('Running migrations against', DB_PATH);
  ensureSchema();
  ensureTimeSlotsTable();
  ensureQueueCodeColumn();
  backfillMissingProbeCodes();

  // --- Optional sample seed (uncomment when you want to create a day’s slots) ---
  // seedDay({ siteId: 1, date: '2025-08-22', loadsTarget: 80, open: '07:00', close: '17:00' });
  // seedDay({ siteId: 2, date: '2025-08-22', loadsTarget: 80, open: '07:00', close: '17:00' });

  console.log('Migrations applied ✅');
}

main();
