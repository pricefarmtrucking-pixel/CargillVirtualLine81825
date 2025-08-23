// migrate.js — ESM
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
function hasCol(tbl, col) {
  return db.prepare(`PRAGMA table_info(${tbl})`).all().some(r => r.name === col);
}

function applySchema() {
  const schemaPath = path.join(__dirname, 'schema.sql');
  if (fs.existsSync(schemaPath)) {
    exec(fs.readFileSync(schemaPath, 'utf8'), 'Applied schema.sql');
  } else {
    exec(`
      CREATE TABLE IF NOT EXISTS time_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        slot_time TEXT NOT NULL,
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
        queue_code TEXT,
        status TEXT DEFAULT 'reserved',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations (site_id, date, queue_code);
    `, 'Applied fallback schema');
  }

  if (!hasCol('slot_reservations', 'queue_code')) {
    exec(`ALTER TABLE slot_reservations ADD COLUMN queue_code TEXT;`, 'Added queue_code');
  }
  if (!hasCol('slot_reservations', 'status')) {
    exec(`ALTER TABLE slot_reservations ADD COLUMN status TEXT DEFAULT 'reserved';`, 'Added status');
  }
  exec(`CREATE INDEX IF NOT EXISTS idx_resv_probe ON slot_reservations (site_id, date, queue_code);`, 'Ensured probe index');
}

function backfillProbeCodes() {
  const rows = db.prepare(`SELECT id FROM slot_reservations WHERE queue_code IS NULL OR queue_code=''`).all();
  if (!rows.length) return;
  const upd = db.prepare(`UPDATE slot_reservations SET queue_code=? WHERE id=?`);
  const tx = db.transaction(() => {
    for (const r of rows) {
      const code = String(Math.floor(1000 + Math.random()*9000));
      upd.run(code, r.id);
    }
  });
  tx();
  console.log(`✓ Backfilled ${rows.length} queue_code(s)`);
}

console.log('Running migrations on', DB_PATH);
applySchema();
backfillProbeCodes();
console.log('Migrations applied.');
