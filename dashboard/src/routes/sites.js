const express = require('express');
const db = require('../db');
const scheduler = require('../scheduler');
const { runScanForSite, runningScans } = require('../scanner');
const { setScanEnabled: setAgentScanEnabled } = require('../agentClient');

const router = express.Router();

router.get('/sites', (req, res) => {
  const sites = db.prepare('SELECT id, name, url, scan_enabled, schedule_cron, last_scan_at, last_scan_status FROM sites ORDER BY name').all();
  const withStatus = sites.map((s) => ({
    ...s,
    scan_enabled: !!s.scan_enabled,
    scan_running: runningScans.has(s.id),
    scheduled: scheduler.isScheduled(s.id),
  }));
  res.json(withStatus);
});

router.post('/sites', (req, res) => {
  const { name, url, api_key, schedule_cron } = req.body;
  if (!name || !url || !api_key) {
    return res.status(400).json({ error: 'name, url, and api_key are required' });
  }
  try {
    const info = db
      .prepare('INSERT INTO sites (name, url, api_key, schedule_cron) VALUES (?, ?, ?, ?)')
      .run(name, url.replace(/\/$/, ''), api_key, schedule_cron || '0 */6 * * *');
    const site = db.prepare('SELECT * FROM sites WHERE id = ?').get(info.lastInsertRowid);
    scheduler.start(site);
    res.status(201).json(site);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/sites/:id', (req, res) => {
  scheduler.stop(Number(req.params.id));
  db.prepare('DELETE FROM sites WHERE id = ?').run(req.params.id);
  res.status(204).end();
});

router.post('/sites/:id/scan/start', async (req, res) => {
  const site = db.prepare('SELECT * FROM sites WHERE id = ?').get(req.params.id);
  if (!site) return res.status(404).json({ error: 'Site not found' });
  try {
    const scanId = await runScanForSite(site);
    res.json({ scan_id: scanId, status: 'completed' });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

router.post('/sites/:id/scan/stop', async (req, res) => {
  const site = db.prepare('SELECT * FROM sites WHERE id = ?').get(req.params.id);
  if (!site) return res.status(404).json({ error: 'Site not found' });

  scheduler.stop(site.id);
  db.prepare('UPDATE sites SET scan_enabled = 0 WHERE id = ?').run(site.id);

  try {
    await setAgentScanEnabled(site, false);
  } catch (err) {
    // Dashboard-side stop still takes effect even if the site is unreachable.
    return res.json({ stopped: true, warning: `Could not reach site to disable remote scanning: ${err.message}` });
  }
  res.json({ stopped: true });
});

router.post('/sites/:id/scan/resume', async (req, res) => {
  const site = db.prepare('SELECT * FROM sites WHERE id = ?').get(req.params.id);
  if (!site) return res.status(404).json({ error: 'Site not found' });

  db.prepare('UPDATE sites SET scan_enabled = 1 WHERE id = ?').run(site.id);
  const updated = db.prepare('SELECT * FROM sites WHERE id = ?').get(site.id);
  scheduler.start(updated);

  try {
    await setAgentScanEnabled(updated, true);
  } catch (err) {
    return res.json({ resumed: true, warning: `Could not reach site to enable remote scanning: ${err.message}` });
  }
  res.json({ resumed: true });
});

router.get('/sites/:id/findings', (req, res) => {
  const latestScan = db
    .prepare('SELECT id FROM scans WHERE site_id = ? AND status = \'completed\' ORDER BY id DESC LIMIT 1')
    .get(req.params.id);
  if (!latestScan) return res.json({ scan_id: null, findings: [] });

  const findings = db
    .prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY is_vulnerable DESC, type, name')
    .all(latestScan.id)
    .map((f) => ({ ...f, vulnerabilities: JSON.parse(f.vulnerabilities_json || '[]'), is_vulnerable: !!f.is_vulnerable }));

  res.json({ scan_id: latestScan.id, findings });
});

module.exports = router;
