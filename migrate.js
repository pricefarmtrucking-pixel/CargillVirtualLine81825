import Database from 'better-sqlite3';
import fs from 'fs';
const db = new Database('data.db');
const sql = fs.readFileSync('schema.sql','utf8');
db.exec(sql);
console.log('Migrations applied.');
