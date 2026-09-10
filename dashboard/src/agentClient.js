const fetch = require('node-fetch');

// Use the ?rest_route= form rather than /wp-json/... — it works on every
// WordPress site regardless of permalink structure (pretty permalinks need
// rewrite rules that a bare/plain-permalink site won't have).
function restUrl(siteUrl, route) {
  const url = new URL('/', siteUrl);
  url.searchParams.set('rest_route', route);
  return url.toString();
}

async function fetchInventory(site) {
  const url = restUrl(site.url, '/saferwp/v1/inventory');
  const res = await fetch(url, {
    headers: { 'x-saferwp-key': site.api_key },
    timeout: 15000,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Agent inventory request failed (${res.status}): ${body.slice(0, 200)}`);
  }
  return res.json();
}

async function setScanEnabled(site, enabled) {
  const url = restUrl(site.url, '/saferwp/v1/scan-toggle');
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'x-saferwp-key': site.api_key, 'content-type': 'application/json' },
    body: JSON.stringify({ enabled }),
  });
  if (!res.ok) {
    throw new Error(`Agent scan-toggle request failed (${res.status})`);
  }
  return res.json();
}

module.exports = { fetchInventory, setScanEnabled };
