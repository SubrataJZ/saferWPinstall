const fetch = require('node-fetch');
const db = require('./db');

const WPSCAN_API_BASE = process.env.WPSCAN_API_BASE || 'https://wpscan.com/api/v3';
const WPSCAN_TOKEN = process.env.WPSCAN_API_TOKEN || '';

// WPScan's free tier grants 25 requests/day. Default to that exact number but
// let it be tuned down (e.g. to leave headroom for manual lookups on wpscan.com).
const DAILY_LIMIT = parseInt(process.env.WPSCAN_DAILY_LIMIT || '25', 10);
// How long a cached vulnerability list is trusted before we're willing to spend
// another request refreatching it. New disclosures don't happen hourly, so a
// long TTL is the main lever that keeps a fleet of sites within a 25/day budget.
const CACHE_TTL_HOURS = parseFloat(process.env.WPSCAN_CACHE_TTL_HOURS || '24');

const getUsageRow = db.prepare('SELECT request_count FROM wpscan_usage WHERE date = ?');
const bumpUsage = db.prepare(`
  INSERT INTO wpscan_usage (date, request_count) VALUES (?, 1)
  ON CONFLICT(date) DO UPDATE SET request_count = request_count + 1
`);
const getCacheRow = db.prepare('SELECT vulnerabilities_json, fetched_at FROM vuln_cache WHERE type = ? AND slug = ?');
const upsertCache = db.prepare(`
  INSERT INTO vuln_cache (type, slug, vulnerabilities_json, fetched_at) VALUES (?, ?, ?, datetime('now'))
  ON CONFLICT(type, slug) DO UPDATE SET vulnerabilities_json = excluded.vulnerabilities_json, fetched_at = excluded.fetched_at
`);

function today() {
  return new Date().toISOString().slice(0, 10);
}

function getTodayUsage() {
  const row = getUsageRow.get(today());
  return row ? row.request_count : 0;
}

function quotaRemaining() {
  return Math.max(0, DAILY_LIMIT - getTodayUsage());
}

function getQuotaStatus() {
  const used = getTodayUsage();
  return { used, limit: DAILY_LIMIT, remaining: Math.max(0, DAILY_LIMIT - used) };
}

function isFresh(fetchedAt) {
  const ageMs = Date.now() - new Date(fetchedAt.replace(' ', 'T') + 'Z').getTime();
  return ageMs < CACHE_TTL_HOURS * 3600 * 1000;
}

/**
 * Looks up known vulnerabilities for a plugin/theme slug (or, for WordPress
 * core, its version string) from the WPScan Vulnerability Database.
 *
 * Cache-first: a fresh cache hit costs nothing. A stale or missing entry
 * costs one live request, UNLESS today's request budget is already spent, in
 * which case stale cache is returned (marked `stale: true`) rather than
 * making a request that would just add to a 429 pile-up, and a slug with no
 * cache at all throws WPSCAN_QUOTA_EXHAUSTED so the caller can report it
 * clearly instead of silently guessing "no known vulnerabilities."
 *
 * Requires a free WPScan API token: https://wpscan.com/api
 */
async function lookupVulnerabilities(type, slugOrVersion) {
  const cacheType = type === 'core' ? 'core' : type;
  const cached = getCacheRow.get(cacheType, slugOrVersion);

  if (cached && isFresh(cached.fetched_at)) {
    return { vulnerabilities: JSON.parse(cached.vulnerabilities_json), fromCache: true, stale: false };
  }

  if (quotaRemaining() <= 0) {
    if (cached) {
      return { vulnerabilities: JSON.parse(cached.vulnerabilities_json), fromCache: true, stale: true };
    }
    const err = new Error(`WPScan daily request budget (${DAILY_LIMIT}) is used up and no cached data exists for ${type}/${slugOrVersion} yet.`);
    err.code = 'WPSCAN_QUOTA_EXHAUSTED';
    throw err;
  }

  if (!WPSCAN_TOKEN) {
    throw new Error('WPSCAN_API_TOKEN is not configured. Get a free key at https://wpscan.com/api and set it in the environment.');
  }

  const endpointType = type === 'theme' ? 'themes' : type === 'core' ? 'wordpresses' : 'plugins';
  const url = `${WPSCAN_API_BASE}/${endpointType}/${encodeURIComponent(slugOrVersion)}`;

  const res = await fetch(url, {
    headers: { Authorization: `Token token=${WPSCAN_TOKEN}` },
  });
  // Count the request against our own budget regardless of outcome (404 included) —
  // WPScan counts it against yours the same way.
  bumpUsage.run(today());

  if (res.status === 404) {
    upsertCache.run(cacheType, slugOrVersion, '[]');
    return { vulnerabilities: [], fromCache: false, stale: false };
  }
  if (res.status === 429) {
    if (cached) {
      return { vulnerabilities: JSON.parse(cached.vulnerabilities_json), fromCache: true, stale: true };
    }
    const err = new Error('WPScan returned 429 (rate limited) and no cached data exists for this item yet.');
    err.code = 'WPSCAN_RATE_LIMITED';
    throw err;
  }
  if (!res.ok) {
    throw new Error(`WPScan API error ${res.status} for ${type}/${slugOrVersion}`);
  }

  const data = await res.json();
  const entry = data[slugOrVersion];
  const vulnerabilities =
    !entry || !Array.isArray(entry.vulnerabilities)
      ? []
      : entry.vulnerabilities.map((v) => ({
          title: v.title,
          cve: (v.references && v.references.cve) || [],
          severity: severityFromCvss(v.cvss),
          fixed_in: v.fixed_in || null,
          published_date: v.published_date || null,
          references: v.references || {},
        }));

  upsertCache.run(cacheType, slugOrVersion, JSON.stringify(vulnerabilities));
  return { vulnerabilities, fromCache: false, stale: false };
}

function severityFromCvss(cvss) {
  const score = cvss && typeof cvss.score === 'number' ? cvss.score : null;
  if (score === null) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

module.exports = { lookupVulnerabilities, getQuotaStatus, DAILY_LIMIT, CACHE_TTL_HOURS };
