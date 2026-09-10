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
  let vulnerabilities = [];
  try {
    vulnerabilities = await lookupVulnerabilities(item.type, item.slug);
  } catch (err) {
    // Don't fail the whole scan over one lookup error (e.g. rate limit); record as unknown.
    insertFinding.run({
      scan_id: scanId,
      site_id: siteId,
      type: item.type,
      slug: item.slug,
      name: item.name || item.slug,
      installed_version: item.version,
      is_vulnerable: 0,
      vulnerabilities_json: JSON.stringify([{ title: `Vulnerability lookup failed: ${err.message}`, severity: 'unknown' }]),
      recommended_version: null,
      recommendation_reason: 'Vulnerability data unavailable this scan.',
    });
    return;
  }

  const applicable = findApplicableVulnerabilities(item.version, vulnerabilities);

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
    recommendation_reason: recommended.reason,
  });
}

module.exports = { runScanForSite, runningScans };
