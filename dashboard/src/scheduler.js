const cron = require('node-cron');
const db = require('./db');
const { runScanForSite } = require('./scanner');

const activeTasks = new Map(); // site_id -> ScheduledTask

function start(site) {
  stop(site.id);
  if (!site.scan_enabled) return;
  if (!cron.validate(site.schedule_cron)) {
    throw new Error(`Invalid cron expression: ${site.schedule_cron}`);
  }
  const task = cron.schedule(site.schedule_cron, async () => {
    try {
      await runScanForSite(site);
    } catch (err) {
      console.error(`[scheduler] scan failed for site ${site.id}:`, err.message);
    }
  });
  activeTasks.set(site.id, task);
}

function stop(siteId) {
  const task = activeTasks.get(siteId);
  if (task) {
    task.stop();
    activeTasks.delete(siteId);
  }
}

function isScheduled(siteId) {
  return activeTasks.has(siteId);
}

function startAllEnabled() {
  const sites = db.prepare('SELECT * FROM sites WHERE scan_enabled = 1').all();
  for (const site of sites) {
    try {
      start(site);
    } catch (err) {
      console.error(`[scheduler] failed to schedule site ${site.id}:`, err.message);
    }
  }
}

module.exports = { start, stop, isScheduled, startAllEnabled };
