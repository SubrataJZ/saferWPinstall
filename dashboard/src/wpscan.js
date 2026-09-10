const fetch = require('node-fetch');

const WPSCAN_API_BASE = 'https://wpscan.com/api/v3';
const WPSCAN_TOKEN = process.env.WPSCAN_API_TOKEN || '';

/**
 * Looks up known vulnerabilities for a plugin or theme slug from the WPScan
 * Vulnerability Database. Returns the raw list of vuln objects WPScan reports
 * for that slug (each entry already scopes the affected version range).
 *
 * Requires a free WPScan API token: https://wpscan.com/api
 */
async function lookupVulnerabilities(type, slug) {
  if (!WPSCAN_TOKEN) {
    throw new Error('WPSCAN_API_TOKEN is not configured. Get a free key at https://wpscan.com/api and set it in the environment.');
  }

  const endpointType = type === 'theme' ? 'themes' : type === 'core' ? 'wordpresses' : 'plugins';
  const url = `${WPSCAN_API_BASE}/${endpointType}/${encodeURIComponent(slug)}`;

  const res = await fetch(url, {
    headers: { Authorization: `Token token=${WPSCAN_TOKEN}` },
  });

  if (res.status === 404) {
    return []; // slug not tracked by WPScan -> assume no known vulns on record
  }
  if (res.status === 429) {
    throw new Error('WPSCAN_RATE_LIMITED');
  }
  if (!res.ok) {
    throw new Error(`WPScan API error ${res.status} for ${type}/${slug}`);
  }

  const data = await res.json();
  const entry = data[slug];
  if (!entry || !Array.isArray(entry.vulnerabilities)) {
    return [];
  }

  return entry.vulnerabilities.map((v) => ({
    title: v.title,
    cve: (v.references && v.references.cve) || [],
    severity: severityFromCvss(v.cvss),
    fixed_in: v.fixed_in || null,
    published_date: v.published_date || null,
    references: v.references || {},
  }));
}

function severityFromCvss(cvss) {
  const score = cvss && typeof cvss.score === 'number' ? cvss.score : null;
  if (score === null) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

module.exports = { lookupVulnerabilities };
