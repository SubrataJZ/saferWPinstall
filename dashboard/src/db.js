const path = require('path');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, '..', 'saferwp.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  url TEXT NOT NULL UNIQUE,
  api_key TEXT NOT NULL,
  scan_enabled INTEGER NOT NULL DEFAULT 1,
  schedule_cron TEXT DEFAULT '0 */6 * * *',
  last_scan_at TEXT,
  last_scan_status TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'running',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  type TEXT NOT NULL, -- 'plugin' | 'theme' | 'core'
  slug TEXT NOT NULL,
  name TEXT,
  installed_version TEXT NOT NULL,
  active INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  slug TEXT NOT NULL,
  name TEXT,
  installed_version TEXT NOT NULL,
  is_vulnerable INTEGER NOT NULL DEFAULT 0,
  vulnerabilities_json TEXT, -- array of {title, cve, severity, fixed_in, published_date, references}
  recommended_version TEXT,
  recommendation_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_site ON findings(site_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_inventory_scan ON inventory(scan_id);

-- One row per (type, slug): vulnerability data is the same for a given plugin/theme
-- regardless of which site or which installed version asked, so every site's scan
-- shares one cached lookup instead of each spending its own WPScan quota on it.
CREATE TABLE IF NOT EXISTS vuln_cache (
  type TEXT NOT NULL,
  slug TEXT NOT NULL,
  vulnerabilities_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (type, slug)
);

-- Tracks how many live WPScan requests we've made today, so we can stop calling
-- out (and fall back to cache) before actually hitting WPScan's own daily limit.
CREATE TABLE IF NOT EXISTS wpscan_usage (
  date TEXT PRIMARY KEY,
  request_count INTEGER NOT NULL DEFAULT 0
);
`);

module.exports = db;
