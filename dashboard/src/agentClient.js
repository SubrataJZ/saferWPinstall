const fetch = require('node-fetch');

async function fetchInventory(site) {
  const url = new URL('/wp-json/saferwp/v1/inventory', site.url).toString();
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
  const url = new URL('/wp-json/saferwp/v1/scan-toggle', site.url).toString();
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
