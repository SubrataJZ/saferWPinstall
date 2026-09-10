const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/overview', (req, res) => {
  const sites = db.prepare('SELECT id, name, url FROM sites').all();

  const summary = sites.map((site) => {
    const latestScan = db
      .prepare("SELECT id, started_at FROM scans WHERE site_id = ? AND status = 'completed' ORDER BY id DESC LIMIT 1")
      .get(site.id);

    if (!latestScan) {
      return { ...site, scanned: false, vulnerable_count: 0, total_items: 0, last_scan_at: null };
    }

    const counts = db
      .prepare('SELECT COUNT(*) AS total, SUM(is_vulnerable) AS vulnerable FROM findings WHERE scan_id = ?')
      .get(latestScan.id);

    return {
      ...site,
      scanned: true,
      last_scan_at: latestScan.started_at,
      total_items: counts.total || 0,
      vulnerable_count: counts.vulnerable || 0,
    };
  });

  res.json({
    site_count: sites.length,
    total_vulnerable: summary.reduce((sum, s) => sum + s.vulnerable_count, 0),
    sites: summary,
  });
});

module.exports = router;
