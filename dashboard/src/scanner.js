const db = require('./db');
const { fetchInventory } = require('./agentClient');
const { lookupVulnerabilities } = require('./wpscan');
const { getVersionHistory } = require('./wordpressOrg');
const { findApplicableVulnerabilities, recommendSafeVersion } = require('./version');

const insertScan = db.prepare(`INSERT INTO scans (site_id, status) VALUES (?, 'running')`);
const finishScan = db.prepare(`UPDATE scans SET status = ?, finished_at = datetime('now'), error = ? WHERE id = ?`);
const insertInventory = db.prepare(`
  INSERT INTO inventory (site_id, scan_id, type, slug, name, installed_version, active)
  VALUES (@site_id, @scan_id, @type, @slug, @name, @installed_version, @active)
`);
const insertFinding = db.prepare(`
  INSERT INTO findings (scan_id, site_id, type, slug, name, installed_version, is_vulnerable, vulnerabilities_json, recommended_version, recommendation_reason)
  VALUES (@scan_id, @site_id, @type, @slug, @name, @installed_version, @is_vulnerable, @vulnerabilities_json, @recommended_version, @recommendation_reason)
`);
const updateSiteAfterScan = db.prepare(`UPDATE sites SET last_scan_at = datetime('now'), last_scan_status = ? WHERE id = ?`);

const runningScans = new Set();

async function runScanForSite(site) {
  if (runningScans.has(site.id)) {
    throw new Error('A scan is already running for this site');
  }
  if (!site.scan_enabled) {
    throw new Error('Scanning is disabled for this site');
  }

  runningScans.add(site.id);
  const scanId = insertScan.run(site.id).lastInsertRowid;

  try {
    const inventory = await fetchInventory(site);
    const items = [
      ...inventory.plugins.map((p) => ({ ...p, type: 'plugin' })),
      ...inventory.themes.map((t) => ({ ...t, type: 'theme' })),
    ];
    if (inventory.wp_version) {
      items.push({ slug: 'wordpress', name: 'WordPress core', version: inventory.wp_version, active: true, type: 'core' });
    }

    for (const item of items) {
      insertInventory.run({
        site_id: site.id,
        scan_id: scanId,
        type: item.type,
        slug: item.slug,
        name: item.name || item.slug,
        installed_version: item.version,
        active: item.active ? 1 : 0,
      });

      await evaluateItem(scanId, site.id, item);
    }

    finishScan.run('completed', null, scanId);
    updateSiteAfterScan.run('completed', site.id);
  } catch (err) {
    finishScan.run('failed', String(err.message || err), scanId);
    updateSiteAfterScan.run('failed', site.id);
    throw err;
  } finally {
    runningScans.delete(site.id);
  }

  return scanId;
}

async function evaluateItem(scanId, siteId, item) {
  // WPScan's core endpoint is keyed by WordPress version, not a "wordpress" slug.
  const lookupKey = item.type === 'core' ? item.version : item.slug;

  let vulnerabilities;
  let stale = false;
  try {
    const result = await lookupVulnerabilities(item.type, lookupKey);
    vulnerabilities = result.vulnerabilities;
    stale = result.stale;
  } catch (err) {
    // Don't fail the whole scan over one lookup error (quota exhausted, rate limit,
    // network blip); record it plainly so it's visible in the findings table rather
    // than silently reported as "safe."
    const reason =
      err.code === 'WPSCAN_QUOTA_EXHAUSTED' || err.code === 'WPSCAN_RATE_LIMITED'
        ? `WPScan lookup skipped: ${err.message}`
        : `Vulnerability lookup failed: ${err.message}`;
    insertFinding.run({
      scan_id: scanId,
      site_id: siteId,
      type: item.type,
      slug: item.slug,
      name: item.name || item.slug,
      installed_version: item.version,
      is_vulnerable: 0,
      vulnerabilities_json: JSON.stringify([{ title: reason, severity: 'unknown' }]),
      recommended_version: null,
      recommendation_reason: 'Vulnerability status unknown this scan — not the same as confirmed safe.',
    });
    return;
  }

  const applicable = findApplicableVulnerabilities(item.version, vulnerabilities);
  const staleNote = stale ? ' (using cached data — today\'s WPScan request budget is used up)' : '';

  let recommended = { recommended_version: null, reason: 'No update source available for this item.' };
  if (item.type !== 'core') {
    try {
      const { versions, latest } = await getVersionHistory(item.type, item.slug);
      const pool = versions.length ? versions : latest ? [latest] : [];
      if (pool.length) {
        recommended = recommendSafeVersion(item.version, pool, vulnerabilities);
      }
    } catch (err) {
      recommended = { recommended_version: null, reason: `Version history unavailable: ${err.message}` };
    }
  }

  insertFinding.run({
    scan_id: scanId,
    site_id: siteId,
    type: item.type,
    slug: item.slug,
    name: item.name || item.slug,
    installed_version: item.version,
    is_vulnerable: applicable.length ? 1 : 0,
    vulnerabilities_json: JSON.stringify(applicable),
    recommended_version: recommended.recommended_version,
    recommendation_reason: recommended.reason + staleNote,
  });
}

module.exports = { runScanForSite, runningScans };
